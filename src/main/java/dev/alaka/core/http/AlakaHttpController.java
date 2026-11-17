package dev.alaka.core.http;

import dev.alaka.core.IdempotencyException;
import dev.alaka.core.RailEventOutcome;
import dev.alaka.core.SpendEngine;
import dev.alaka.core.SpendGateway;
import dev.alaka.core.SpendRequest;
import dev.alaka.mudra.MudraException;
import dev.alaka.nidhi.IntentView;
import dev.alaka.nidhi.NidhiException;
import dev.alaka.yaksha.RailException;
import dev.alaka.yaksha.StripeWebhookHandler;
import dev.alaka.yaksha.WebhookRejectedException;
import java.util.Objects;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The HTTP surface: a thin translation layer over {@link SpendGateway}, {@link SpendEngine} and
 * {@link StripeWebhookHandler}. No business rule lives here; it only maps outcomes onto status
 * codes. JSON field names are snake_case.
 *
 * <ul>
 *   <li>{@code POST /v1/mandates}: register the mandate a signed Mudra token grants (201).
 *   <li>{@code POST /v1/mandates/{id}/revoke}: revoke, irreversibly (200).
 *   <li>{@code POST /v1/spends}: header {@code X-Mudra-Token}, body = spend request + signed
 *       {@code quote_token}. 200 when the intent is terminal, 202 while it is still settling (rail
 *       processing, or recovery could not reach the rail; the recovery sweeper will finish it).
 *   <li>{@code POST /v1/webhooks/stripe}: a Stripe delivery, verified over its raw bytes (200, or
 *       400 if the signature does not verify).
 * </ul>
 *
 * <p>Error mapping: 409 + {@code Retry-After} for a request still in flight under the same key;
 * 422 for a key reused with a different payload, an invalid or mismatched Mudra token, a missing,
 * untrusted, tampered or mismatched quote token, quote drift, or a currency mismatch; 402 for a budget or per-transaction cap breach (SG003); 403 for an
 * inactive, revoked or expired mandate (SG001) or a merchant outside the allowlist (SG008); 409
 * for an illegal state transition (SG004) or an already registered mandate; 404 for an unknown
 * mandate; 503 + {@code Retry-After} when serialization retries ran out.
 */
@RestController
@RequestMapping("/v1")
public class AlakaHttpController {

    /** {@code POST /v1/mandates} body. */
    public record RegisterMandateBody(String token) {
    }

    /** {@code POST /v1/mandates/{id}/revoke} body. */
    public record RevokeBody(String reason) {
    }

    /** Mandate response. */
    public record MandateResponse(UUID mandateId, String status) {
    }

    /**
     * {@code POST /v1/spends} body. {@code quoteToken} is the approving party's signed approval of
     * exactly this request ({@code mudraq1....}); there is no unsigned form.
     */
    public record SpendBody(UUID mandateId, String agentId, String idempotencyKey, String merchantId,
            String currency, long amountMinor, String quoteToken) {
    }

    /** An intent as returned to the agent. */
    public record IntentResponse(UUID intentId, String status, long authorizedAmountMinor, long capturedAmountMinor,
            String railPaymentIntentId, boolean replayed) {

        static IntentResponse of(IntentView intent, boolean replayed) {
            return new IntentResponse(intent.intentId(), intent.status().name(), intent.authorizedAmountMinor(),
                    intent.capturedAmountMinor(), intent.railPaymentIntentId(), replayed);
        }
    }

    /** Webhook response. */
    public record WebhookResponse(String disposition) {
    }

    /** Error response: {@code {"error": {"type": ..., "code": ..., "message": ...}}}. */
    public record ErrorResponse(ErrorDetail error) {
    }

    /** Error detail. */
    public record ErrorDetail(String type, String code, String message) {
    }

    private final SpendGateway gateway;
    private final SpendEngine engine;
    private final StripeWebhookHandler webhooks;

    public AlakaHttpController(SpendGateway gateway, SpendEngine engine, StripeWebhookHandler webhooks) {
        this.gateway = Objects.requireNonNull(gateway, "gateway");
        this.engine = Objects.requireNonNull(engine, "engine");
        this.webhooks = Objects.requireNonNull(webhooks, "webhooks");
    }

    @PostMapping("/mandates")
    public ResponseEntity<MandateResponse> registerMandate(@RequestBody RegisterMandateBody body) {
        UUID mandateId = gateway.registerMandate(body.token());
        return ResponseEntity.status(HttpStatus.CREATED).body(new MandateResponse(mandateId, "ACTIVE"));
    }

    @PostMapping("/mandates/{mandateId}/revoke")
    public MandateResponse revokeMandate(@PathVariable UUID mandateId, @RequestBody(required = false) RevokeBody body) {
        engine.revokeMandate(mandateId, body == null || body.reason() == null ? "revoked via API" : body.reason());
        return new MandateResponse(mandateId, "REVOKED");
    }

    @PostMapping("/spends")
    public ResponseEntity<IntentResponse> spend(@RequestHeader("X-Mudra-Token") String token, @RequestBody SpendBody body) {
        SpendRequest request = new SpendRequest(body.mandateId(), body.agentId(), body.idempotencyKey(),
                body.merchantId(), body.currency(), body.amountMinor());
        try {
            var result = gateway.execute(token, body.quoteToken(), request);
            IntentView intent = result.intent();
            HttpStatus status = intent.status().isTerminal() ? HttpStatus.OK : HttpStatus.ACCEPTED;
            return ResponseEntity.status(status).body(IntentResponse.of(intent, result.replayed()));
        } catch (RailException e) {
            // The rail outcome is unknown and recovery could not reach it either. The intent holds
            // its reservation and the recovery sweeper will settle it; retrying with the same key
            // answers 409 until then.
            IntentView pending = engine.findIntent(request.agentId(), request.idempotencyKey()).orElseThrow(() -> e);
            return ResponseEntity.status(HttpStatus.ACCEPTED).body(IntentResponse.of(pending, false));
        }
    }

    @PostMapping("/webhooks/stripe")
    public WebhookResponse stripeWebhook(@RequestHeader(value = "Stripe-Signature", required = false) String signature,
            @RequestBody byte[] rawBody) {
        RailEventOutcome outcome = webhooks.handle(signature, rawBody);
        return new WebhookResponse(outcome.disposition().name());
    }

    // ------------------------------------------------------------------------------------------
    // Error mapping

    @ExceptionHandler(IdempotencyException.InFlight.class)
    ResponseEntity<ErrorResponse> inFlight(IdempotencyException.InFlight e) {
        long seconds = Math.max(1, (e.retryAfter().toMillis() + 999) / 1000);
        return ResponseEntity.status(HttpStatus.CONFLICT).header("Retry-After", Long.toString(seconds))
                .body(error("idempotency_error", "IdempotencyKeyInFlight", e));
    }

    @ExceptionHandler(IdempotencyException.PayloadMismatch.class)
    ResponseEntity<ErrorResponse> payloadMismatch(IdempotencyException.PayloadMismatch e) {
        return respond(HttpStatus.UNPROCESSABLE_ENTITY, "idempotency_error", "IdempotencyKeyPayloadMismatch", e);
    }

    @ExceptionHandler(MudraException.class)
    ResponseEntity<ErrorResponse> mudra(MudraException e) {
        String code = switch (e) {
            case MudraException.QuoteDrift drift -> "QuoteDrift." + drift.reason();
            case MudraException.InvalidQuote quote -> "InvalidQuote." + quote.reason();
            default -> e.getClass().getSimpleName();
        };
        return respond(HttpStatus.UNPROCESSABLE_ENTITY, "mandate_error", code, e);
    }

    @ExceptionHandler(NidhiException.class)
    ResponseEntity<ErrorResponse> nidhi(NidhiException e) {
        HttpStatus status = switch (e) {
            case NidhiException.BudgetExceeded b -> HttpStatus.PAYMENT_REQUIRED;
            case NidhiException.MandateInactive m -> HttpStatus.FORBIDDEN;
            case NidhiException.MerchantNotAllowed m -> HttpStatus.FORBIDDEN;
            case NidhiException.CurrencyMismatch c -> HttpStatus.UNPROCESSABLE_ENTITY;
            case NidhiException.IllegalStateTransition i -> HttpStatus.CONFLICT;
            case NidhiException.UniqueViolation u -> HttpStatus.CONFLICT;
            case NidhiException.SerializationFailure s -> HttpStatus.SERVICE_UNAVAILABLE;
            case NidhiException.DeadlockDetected d -> HttpStatus.SERVICE_UNAVAILABLE;
            default -> HttpStatus.INTERNAL_SERVER_ERROR;
        };
        ResponseEntity.BodyBuilder builder = ResponseEntity.status(status);
        if (status == HttpStatus.SERVICE_UNAVAILABLE) {
            builder.header("Retry-After", "1");
        }
        String message = e.getMessage() == null ? "" : e.getMessage().lines().findFirst().orElse("");
        return builder.body(new ErrorResponse(new ErrorDetail("ledger_error", e.sqlState(), message)));
    }

    @ExceptionHandler(WebhookRejectedException.class)
    ResponseEntity<ErrorResponse> webhookRejected(WebhookRejectedException e) {
        return respond(HttpStatus.BAD_REQUEST, "webhook_error", e.reason().name(), e);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    ResponseEntity<ErrorResponse> badArgument(IllegalArgumentException e) {
        HttpStatus status = e.getMessage() != null && e.getMessage().startsWith("Unknown ")
                ? HttpStatus.NOT_FOUND : HttpStatus.BAD_REQUEST;
        return respond(status, "invalid_request_error", status == HttpStatus.NOT_FOUND ? "resource_missing" : "invalid", e);
    }

    private static ResponseEntity<ErrorResponse> respond(HttpStatus status, String type, String code, Exception e) {
        return ResponseEntity.status(status).body(error(type, code, e));
    }

    private static ErrorResponse error(String type, String code, Exception e) {
        return new ErrorResponse(new ErrorDetail(type, code, e.getMessage()));
    }
}
