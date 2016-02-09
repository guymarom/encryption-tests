package benchmarks;

import ciphers.AesCipher;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import org.openjdk.jmh.runner.options.TimeValue;

public class EncryptionBenchmark {

  public static void main(final String[] args) throws RunnerException {

    Options options = new OptionsBuilder()
      .include(EncryptionBenchmark.class.getSimpleName())
      .measurementTime(TimeValue.seconds(1))
      .measurementIterations(10)
      .warmupIterations(3)
      .forks(1)
      .build();

    new Runner(options).run();
  }

  @State(Scope.Benchmark)
  public static class BenchmarkState {
    volatile AesCipher cipher = new AesCipher();
  }

  @Benchmark
  public void encryptDecrypt(BenchmarkState state) throws Exception {
    state.cipher.decrypt(state.cipher.encrypt("message"));
  }

}
