/*
 * CT-KAT raw-trace adapter for the pinned official dudect engine.
 *
 * This file is CT-KAT code (MIT). It includes the unmodified upstream
 * dudect.h and calls its actual prepare_percentiles(), update_statistics(),
 * max_test(), and t_compute() implementation. The first input trace supplies
 * the discarded percentile-calibration batch; the second supplies the
 * analyzed batch. Input measurement remains CT-KAT's responsibility.
 */

#define DUDECT_IMPLEMENTATION
#include "dudect.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CTKAT_TRACE_MAGIC "CTKAT-DUDECT-TRACE-V1"
#define CTKAT_UPSTREAM_REVISION "dc269651fb2567e46755cfb2a13d3875592968b5"

typedef struct {
  size_t count;
  uint8_t *classes;
  int64_t *cycles;
} ctkat_trace_t;

/* dudect.h requires target callbacks even though this stats-only adapter
 * never invokes dudect_main(). */
void prepare_inputs(dudect_config_t *config, uint8_t *input_data,
                    uint8_t *classes) {
  (void)config;
  (void)input_data;
  (void)classes;
}

uint8_t do_one_computation(uint8_t *data) {
  return data == NULL ? 0 : data[0];
}

static void free_trace(ctkat_trace_t *trace) {
  free(trace->classes);
  free(trace->cycles);
  memset(trace, 0, sizeof(*trace));
}

static int read_trace(const char *path, ctkat_trace_t *trace) {
  FILE *file = fopen(path, "r");
  if (file == NULL) {
    fprintf(stderr, "cannot open trace %s: %s\n", path, strerror(errno));
    return -1;
  }

  char magic[64] = {0};
  unsigned long long declared = 0;
  if (fscanf(file, "%63s %llu", magic, &declared) != 2 ||
      strcmp(magic, CTKAT_TRACE_MAGIC) != 0 || declared > SIZE_MAX) {
    fprintf(stderr, "invalid trace header in %s\n", path);
    fclose(file);
    return -1;
  }
  if (declared == 0) {
    fprintf(stderr, "empty trace in %s\n", path);
    fclose(file);
    return -1;
  }

  trace->count = (size_t)declared;
  trace->classes = calloc(trace->count, sizeof(*trace->classes));
  trace->cycles = calloc(trace->count, sizeof(*trace->cycles));
  if (trace->classes == NULL || trace->cycles == NULL) {
    fprintf(stderr, "allocation failure reading %s\n", path);
    fclose(file);
    free_trace(trace);
    return -1;
  }

  for (size_t i = 0; i < trace->count; i++) {
    unsigned int clazz = 0;
    int64_t cycles = 0;
    if (fscanf(file, "%u,%" SCNd64, &clazz, &cycles) != 2 || clazz > 1) {
      fprintf(stderr, "invalid trace row %zu in %s\n", i, path);
      fclose(file);
      free_trace(trace);
      return -1;
    }
    trace->classes[i] = (uint8_t)clazz;
    trace->cycles[i] = cycles;
  }

  char trailing[2] = {0};
  if (fscanf(file, "%1s", trailing) == 1) {
    fprintf(stderr, "unexpected trailing data in %s\n", path);
    fclose(file);
    free_trace(trace);
    return -1;
  }
  fclose(file);
  return 0;
}

static void print_json_double(double value) {
  if (isfinite(value)) {
    printf("%.17g", value);
  } else {
    printf("null");
  }
}

static double sample_variance(const ttest_ctx_t *test, int clazz) {
  if (test->n[clazz] < 2) {
    return NAN;
  }
  return test->m2[clazz] / (test->n[clazz] - 1);
}

static const char *test_kind(size_t index) {
  if (index == 0) {
    return "first-order-uncropped";
  }
  if (index <= DUDECT_NUMBER_PERCENTILES) {
    return "first-order-cropped";
  }
  return "second-order";
}

static int init_stats_context(dudect_ctx_t *ctx, dudect_config_t *config) {
  memset(ctx, 0, sizeof(*ctx));
  ctx->config = config;
  ctx->percentiles =
      calloc(DUDECT_NUMBER_PERCENTILES, sizeof(*ctx->percentiles));
  if (ctx->percentiles == NULL) {
    return -1;
  }
  for (size_t i = 0; i < DUDECT_TESTS; i++) {
    ctx->ttest_ctxs[i] = calloc(1, sizeof(*ctx->ttest_ctxs[i]));
    if (ctx->ttest_ctxs[i] == NULL) {
      return -1;
    }
    t_init(ctx->ttest_ctxs[i]);
  }
  return 0;
}

static void free_stats_context(dudect_ctx_t *ctx) {
  for (size_t i = 0; i < DUDECT_TESTS; i++) {
    free(ctx->ttest_ctxs[i]);
  }
  free(ctx->percentiles);
  free(ctx->exec_times);
  free(ctx->classes);
}

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: %s CALIBRATION_TRACE ANALYSIS_TRACE\n", argv[0]);
    return 2;
  }

  ctkat_trace_t calibration = {0};
  ctkat_trace_t analysis = {0};
  if (read_trace(argv[1], &calibration) != 0 ||
      read_trace(argv[2], &analysis) != 0) {
    free_trace(&calibration);
    free_trace(&analysis);
    return 2;
  }
  if (calibration.count == SIZE_MAX || analysis.count == SIZE_MAX) {
    fprintf(stderr, "trace is too large\n");
    free_trace(&calibration);
    free_trace(&analysis);
    return 2;
  }

  dudect_config_t config = {.chunk_size = 1, .number_measurements = 0};
  dudect_ctx_t ctx;
  if (init_stats_context(&ctx, &config) != 0) {
    fprintf(stderr, "statistics context allocation failure\n");
    free_stats_context(&ctx);
    free_trace(&calibration);
    free_trace(&analysis);
    return 2;
  }

  /*
   * Upstream measure() records N-1 differences in an N-element zeroed
   * buffer. Add that trailing zero so prepare_percentiles() sees exactly the
   * representation it sees in dudect_main()'s discarded first batch.
   */
  config.number_measurements = calibration.count + 1;
  ctx.exec_times = calloc(config.number_measurements, sizeof(*ctx.exec_times));
  if (ctx.exec_times == NULL) {
    fprintf(stderr, "calibration allocation failure\n");
    free_stats_context(&ctx);
    free_trace(&calibration);
    free_trace(&analysis);
    return 2;
  }
  memcpy(ctx.exec_times, calibration.cycles,
         calibration.count * sizeof(*ctx.exec_times));
  prepare_percentiles(&ctx);
  free(ctx.exec_times);
  ctx.exec_times = NULL;

  /*
   * Add the same trailing slot and set number_measurements=N+1. The unmodified
   * upstream update_statistics() then consumes analysis rows [10, N), exactly
   * matching its "discard first few" and N-1 loop bounds.
   */
  config.number_measurements = analysis.count + 1;
  ctx.exec_times = calloc(config.number_measurements, sizeof(*ctx.exec_times));
  ctx.classes = calloc(config.number_measurements, sizeof(*ctx.classes));
  if (ctx.exec_times == NULL || ctx.classes == NULL) {
    fprintf(stderr, "analysis allocation failure\n");
    free_stats_context(&ctx);
    free_trace(&calibration);
    free_trace(&analysis);
    return 2;
  }
  memcpy(ctx.exec_times, analysis.cycles,
         analysis.count * sizeof(*ctx.exec_times));
  memcpy(ctx.classes, analysis.classes,
         analysis.count * sizeof(*ctx.classes));

  size_t negative_dropped = 0;
  for (size_t i = 10; i < analysis.count; i++) {
    if (analysis.cycles[i] < 0) {
      negative_dropped++;
    }
  }
  update_statistics(&ctx);

  ttest_ctx_t *winning = max_test(&ctx);
  size_t winning_index = 0;
  for (size_t i = 0; i < DUDECT_TESTS; i++) {
    if (ctx.ttest_ctxs[i] == winning) {
      winning_index = i;
      break;
    }
  }

  int enough = 0;
  for (size_t i = 0; i < DUDECT_TESTS; i++) {
    if (ctx.ttest_ctxs[i]->n[0] > DUDECT_ENOUGH_MEASUREMENTS &&
        ctx.ttest_ctxs[i]->n[1] >= 2) {
      enough = 1;
      break;
    }
  }

  double winning_t =
      winning->n[0] >= 2 && winning->n[1] >= 2 ? t_compute(winning) : NAN;
  double max_abs_t = fabs(winning_t);
  double winning_n = winning->n[0] + winning->n[1];
  double max_tau =
      winning_n > 0 && isfinite(max_abs_t)
          ? max_abs_t / sqrt(winning_n)
          : (isinf(max_abs_t) ? INFINITY : NAN);
  double detection_estimate =
      max_tau > 0 && isfinite(max_tau) ? 25.0 / (max_tau * max_tau)
                                      : (max_tau == 0 ? INFINITY : NAN);
  const char *status =
      !enough ? "INSUFFICIENT"
              : (max_abs_t > t_threshold_moderate ? "FAIL" : "PASS");

  printf("{");
  printf("\"schema_version\":\"1.0\",");
  printf("\"upstream_revision\":\"%s\",", CTKAT_UPSTREAM_REVISION);
  printf("\"status\":\"%s\",", status);
  printf("\"enough_measurements\":%s,", enough ? "true" : "false");
  printf("\"minimum_class0_measurements\":%d,",
         DUDECT_ENOUGH_MEASUREMENTS + 1);
  printf("\"protocol_test_count\":%d,", DUDECT_TESTS);
  printf("\"percentile_test_count\":%d,", DUDECT_NUMBER_PERCENTILES);
  printf("\"calibration_input_count\":%zu,", calibration.count);
  printf("\"analysis_input_count\":%zu,", analysis.count);
  printf("\"discarded_initial_count\":%zu,",
         analysis.count < 10 ? analysis.count : (size_t)10);
  printf("\"dropped_negative_count\":%zu,", negative_dropped);
  printf("\"max_test_index\":%zu,", winning_index);
  printf("\"max_test_kind\":\"%s\",", test_kind(winning_index));
  printf("\"max_abs_t\":");
  print_json_double(max_abs_t);
  printf(",\"max_abs_t_nonfinite\":%s,", isfinite(max_abs_t) ? "false" : "true");
  printf("\"max_tau\":");
  print_json_double(max_tau);
  printf(",\"detection_estimate\":");
  print_json_double(detection_estimate);
  printf(",\"tests\":[");

  for (size_t i = 0; i < DUDECT_TESTS; i++) {
    ttest_ctx_t *test = ctx.ttest_ctxs[i];
    double t_value =
        test->n[0] >= 2 && test->n[1] >= 2 ? t_compute(test) : NAN;
    double variance0 = sample_variance(test, 0);
    double variance1 = sample_variance(test, 1);
    int eligible = test->n[0] > DUDECT_ENOUGH_MEASUREMENTS &&
                   test->n[1] >= 2 && !isnan(t_value);
    if (i != 0) {
      printf(",");
    }
    printf("{\"index\":%zu,\"kind\":\"%s\",", i, test_kind(i));
    if (i > 0 && i <= DUDECT_NUMBER_PERCENTILES) {
      printf("\"crop_index\":%zu,\"crop_threshold\":%" PRId64 ",", i - 1,
             ctx.percentiles[i - 1]);
    } else {
      printf("\"crop_index\":null,\"crop_threshold\":null,");
    }
    printf("\"n0\":%.0f,\"n1\":%.0f,", test->n[0], test->n[1]);
    printf("\"mean0\":");
    print_json_double(test->mean[0]);
    printf(",\"mean1\":");
    print_json_double(test->mean[1]);
    printf(",\"var0\":");
    print_json_double(variance0);
    printf(",\"var1\":");
    print_json_double(variance1);
    printf(",\"t_score\":");
    print_json_double(t_value);
    printf(",\"t_nonfinite\":%s,", isfinite(t_value) ? "false" : "true");
    printf("\"abs_t_score\":");
    print_json_double(fabs(t_value));
    printf(",\"eligible\":%s}", eligible ? "true" : "false");
  }
  printf("]}\n");

  free_stats_context(&ctx);
  free_trace(&calibration);
  free_trace(&analysis);
  return 0;
}
