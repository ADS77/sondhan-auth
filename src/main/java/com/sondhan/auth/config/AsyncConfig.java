package com.sondhan.auth.config;

import java.util.concurrent.Executor;
import java.util.concurrent.ThreadPoolExecutor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.AsyncConfigurer;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

/**
 * Configures a bounded thread pool for {@code @Async} tasks (primarily audit log writes).
 *
 * <p>Pool sizing rationale:
 * <ul>
 *   <li>Core threads: kept alive to avoid cold-start latency on each audit write</li>
 *   <li>Max threads: capped so audit logging never starves the request thread pool</li>
 *   <li>Queue capacity: bounded — if the queue fills, the caller thread executes the task
 *       (CallerRunsPolicy) rather than dropping it silently</li>
 * </ul>
 *
 * <p>All values are overridable via {@code application.yml} / environment variables.
 */
@Configuration
public class AsyncConfig implements AsyncConfigurer {

  private static final Logger log = LoggerFactory.getLogger(AsyncConfig.class);

  private final int corePoolSize;
  private final int maxPoolSize;
  private final int queueCapacity;
  private final int keepAliveSeconds;

  public AsyncConfig(
      @Value("${app.async.core-pool-size:4}") int corePoolSize,
      @Value("${app.async.max-pool-size:8}") int maxPoolSize,
      @Value("${app.async.queue-capacity:500}") int queueCapacity,
      @Value("${app.async.keep-alive-seconds:60}") int keepAliveSeconds) {
    this.corePoolSize = corePoolSize;
    this.maxPoolSize = maxPoolSize;
    this.queueCapacity = queueCapacity;
    this.keepAliveSeconds = keepAliveSeconds;
  }

  /**
   * Primary async executor — used by {@code @Async} without a qualifier.
   * Named "auditExecutor" so it can also be referenced explicitly if needed.
   */
  @Bean(name = "auditExecutor")
  @Override
  public Executor getAsyncExecutor() {
    ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();

    executor.setCorePoolSize(corePoolSize);
    executor.setMaxPoolSize(maxPoolSize);
    executor.setQueueCapacity(queueCapacity);
    executor.setKeepAliveSeconds(keepAliveSeconds);
    executor.setThreadNamePrefix("audit-");

    // CallerRunsPolicy: if the pool + queue are full, the calling thread executes the task.
    // This provides back-pressure and guarantees audit entries are never silently dropped.
    executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());

    // Wait up to 30 s for in-flight audit tasks to complete before shutdown
    executor.setWaitForTasksToCompleteOnShutdown(true);
    executor.setAwaitTerminationSeconds(30);

    executor.initialize();

    log.info(
        "Audit async executor initialized — core={}, max={}, queue={}",
        corePoolSize, maxPoolSize, queueCapacity);

    return executor;
  }

  @Override
  public org.springframework.aop.interceptor.AsyncUncaughtExceptionHandler
      getAsyncUncaughtExceptionHandler() {
    return (throwable, method, params) ->
        log.error(
            "Uncaught exception in async method {}: {}",
            method.getName(),
            throwable.getMessage(),
            throwable);
  }
}
