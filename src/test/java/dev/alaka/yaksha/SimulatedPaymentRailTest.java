package dev.alaka.yaksha;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.alaka.yaksha.ConfirmBehavior.RailFault;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;

class SimulatedPaymentRailTest {

    private final SimulatedPaymentRail rail = new SimulatedPaymentRail();

    private RailPaymentIntent create(UUID intentId, long amount) {
        return rail.createUnconfirmed("create_" + intentId, intentId, "m", "USD", amount);
    }

    @Test
    void createIsIdempotentAndMovesNoMoney() {
        UUID id = UUID.randomUUID();
        RailPaymentIntent first = create(id, 500);
        assertThat(create(id, 500)).isEqualTo(first);
        assertThat(first.status()).isEqualTo(RailPiStatus.REQUIRES_CONFIRMATION);
        assertThat(rail.totalChargedMinor()).isZero();
        assertThat(rail.paymentIntents()).containsExactly(first);
    }

    @Test
    void confirmChargesOnceAndReplaysIdempotently() {
        UUID id = UUID.randomUUID();
        String pi = create(id, 500).piId();
        rail.setConfirmBehavior(id, ConfirmBehavior.succeedPartial(300));
        assertThat(rail.confirm(pi, "confirm_" + id).chargedMinor()).isEqualTo(300);
        assertThat(rail.confirm(pi, "confirm_" + id).chargedMinor()).isEqualTo(300);
        assertThat(rail.totalChargedMinor()).isEqualTo(300);
    }

    @Test
    void cancelIsRejectedWhileProcessingAndAfterSuccess() {
        UUID id = UUID.randomUUID();
        String pi = create(id, 500).piId();
        rail.setConfirmBehavior(id, ConfirmBehavior.enterProcessing());
        rail.confirm(pi, "c");
        assertThatThrownBy(() -> rail.cancel(pi))
                .isInstanceOfSatisfying(RailException.CancelRejected.class,
                        e -> assertThat(e.statusAtRejection()).isEqualTo(RailPiStatus.PROCESSING));
        rail.resolveProcessingAsSucceeded(pi, 0);
        assertThat(rail.retrieve(pi).chargedMinor()).isEqualTo(500);
        assertThatThrownBy(() -> rail.cancel(pi))
                .isInstanceOfSatisfying(RailException.CancelRejected.class,
                        e -> assertThat(e.statusAtRejection()).isEqualTo(RailPiStatus.SUCCEEDED));
    }

    @Test
    void canceledPaymentIntentRejectsLateConfirm() {
        UUID id = UUID.randomUUID();
        String pi = create(id, 500).piId();
        assertThat(rail.cancel(pi).status()).isEqualTo(RailPiStatus.CANCELED);
        assertThatThrownBy(() -> rail.confirm(pi, "c")).isInstanceOf(RailException.ConfirmRejected.class);
        assertThatThrownBy(() -> rail.cancel(pi)).isInstanceOf(RailException.CancelRejected.class);
        assertThat(rail.totalChargedMinor()).isZero();
    }

    @Test
    void faultsAreOneShotAndDistinguishApplied() {
        UUID lost = UUID.randomUUID();
        rail.setCreateFault(lost, RailFault.TIMEOUT_BEFORE_APPLY);
        assertThatThrownBy(() -> create(lost, 100)).isInstanceOf(RailException.Timeout.class);
        assertThat(rail.findByIntentId(lost)).isEmpty();
        assertThat(create(lost, 100).status()).isEqualTo(RailPiStatus.REQUIRES_CONFIRMATION);

        UUID applied = UUID.randomUUID();
        String pi = create(applied, 100).piId();
        rail.setConfirmBehavior(applied, ConfirmBehavior.succeedFull().withFault(RailFault.TIMEOUT_AFTER_APPLY));
        assertThatThrownBy(() -> rail.confirm(pi, "c")).isInstanceOf(RailException.Timeout.class);
        assertThat(rail.retrieve(pi).status()).isEqualTo(RailPiStatus.SUCCEEDED);
        assertThat(rail.confirm(pi, "c").status()).isEqualTo(RailPiStatus.SUCCEEDED);

        UUID dropped = UUID.randomUUID();
        String pi2 = create(dropped, 100).piId();
        rail.setConfirmBehavior(dropped, ConfirmBehavior.succeedFull().withFault(RailFault.TIMEOUT_BEFORE_APPLY));
        assertThatThrownBy(() -> rail.confirm(pi2, "c")).isInstanceOf(RailException.Timeout.class);
        assertThat(rail.retrieve(pi2).status()).isEqualTo(RailPiStatus.REQUIRES_CONFIRMATION);
        assertThat(rail.confirm(pi2, "c").status()).isEqualTo(RailPiStatus.SUCCEEDED);
    }

    @Test
    void racingConfirmsAndCancelsChargeAtMostOnce() throws Exception {
        rail.setLatency(Duration.ofMillis(1), Duration.ofMillis(5));
        for (int round = 0; round < 20; round++) {
            UUID id = UUID.randomUUID();
            String pi = create(id, 100).piId();
            CountDownLatch start = new CountDownLatch(1);
            List<Future<RailPaymentIntent>> calls = new ArrayList<>();
            try (ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
                for (int i = 0; i < 20; i++) {
                    boolean cancel = i % 2 == 0;
                    calls.add(pool.submit(() -> {
                        start.await();
                        try {
                            return cancel ? rail.cancel(pi) : rail.confirm(pi, "c");
                        } catch (RailException e) {
                            return null;
                        }
                    }));
                }
                start.countDown();
            }
            for (Future<RailPaymentIntent> call : calls) {
                call.get();
            }
            RailPaymentIntent end = rail.retrieve(pi);
            assertThat(end.status()).isIn(RailPiStatus.SUCCEEDED, RailPiStatus.CANCELED);
            assertThat(end.chargedMinor()).isEqualTo(end.status() == RailPiStatus.SUCCEEDED ? 100 : 0);
        }
        long succeeded = rail.paymentIntents().stream().filter(p -> p.status() == RailPiStatus.SUCCEEDED).count();
        assertThat(rail.totalChargedMinor()).isEqualTo(succeeded * 100);
    }

    @Test
    void unknownPaymentIntentIsReported() {
        assertThatThrownBy(() -> rail.retrieve("pi_nope")).isInstanceOf(RailException.UnknownPaymentIntent.class);
    }
}
