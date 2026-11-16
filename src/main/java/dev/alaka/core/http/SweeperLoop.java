package dev.alaka.core.http;

import dev.alaka.yaksha.YakshaRecoverySweeper;
import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.SmartLifecycle;

/**
 * Runs {@link YakshaRecoverySweeper#sweepOnce()} on a virtual thread for as long as the application
 * runs. Several instances may run against one database: claims use {@code FOR UPDATE SKIP LOCKED}.
 */
final class SweeperLoop implements SmartLifecycle {

    private static final Logger LOG = LoggerFactory.getLogger(SweeperLoop.class);

    private final YakshaRecoverySweeper sweeper;
    private final Duration interval;
    private volatile Thread thread;

    SweeperLoop(YakshaRecoverySweeper sweeper, Duration interval) {
        this.sweeper = sweeper;
        this.interval = interval;
    }

    @Override
    public void start() {
        if (sweeper == null || interval.isZero() || interval.isNegative()) {
            LOG.info("recovery sweeper disabled (interval {}, sweeper {})", interval, sweeper == null ? "n/a" : "ready");
            return;
        }
        thread = Thread.ofVirtual().name("yaksha-sweeper").start(this::loop);
    }

    private void loop() {
        while (!Thread.currentThread().isInterrupted()) {
            try {
                YakshaRecoverySweeper.SweepReport report = sweeper.sweepOnce();
                if (report.claimed() > 0) {
                    LOG.info("recovery sweep: {}", report);
                }
            } catch (RuntimeException e) {
                LOG.warn("recovery sweep failed; retrying after {}", interval, e);
            }
            try {
                Thread.sleep(interval);
            } catch (InterruptedException e) {
                return;
            }
        }
    }

    @Override
    public void stop() {
        Thread running = thread;
        thread = null;
        if (running != null) {
            running.interrupt();
        }
    }

    @Override
    public boolean isRunning() {
        return thread != null;
    }
}
