package dev.alaka.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

import org.junit.jupiter.api.Test;

/** Unit tests of {@link RuntimeMode} CLI-name parsing. */
class RuntimeModeTest {

    @Test
    void parsesEachDocumentedModeValue() {
        assertThat(RuntimeMode.fromCliName("naive")).isSameAs(RuntimeMode.NAIVE);
        assertThat(RuntimeMode.fromCliName("hardened-pessimistic"))
                .isSameAs(RuntimeMode.HARDENED_PESSIMISTIC);
        assertThat(RuntimeMode.fromCliName("hardened-ssi")).isSameAs(RuntimeMode.HARDENED_SSI);
    }

    @Test
    void exposesExactlyTheThreeDocumentedCliNames() {
        assertThat(RuntimeMode.values())
                .extracting(RuntimeMode::cliName)
                .containsExactly("naive", "hardened-pessimistic", "hardened-ssi");
    }

    @Test
    void rejectsUnknownValueAndListsTheValidOnes() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> RuntimeMode.fromCliName("hardened"))
                .withMessageContaining("'hardened'")
                .withMessageContaining("naive, hardened-pessimistic, hardened-ssi");
    }

    @Test
    void matchesExactlyWithoutTrimmingOrCaseFolding() {
        assertThatIllegalArgumentException().isThrownBy(() -> RuntimeMode.fromCliName("NAIVE"));
        assertThatIllegalArgumentException().isThrownBy(() -> RuntimeMode.fromCliName(" naive"));
        assertThatIllegalArgumentException().isThrownBy(() -> RuntimeMode.fromCliName("naive "));
        assertThatIllegalArgumentException().isThrownBy(() -> RuntimeMode.fromCliName(""));
        assertThatIllegalArgumentException()
                .isThrownBy(() -> RuntimeMode.fromCliName("--mode=naive"));
    }

    @Test
    void rejectsNull() {
        assertThatNullPointerException().isThrownBy(() -> RuntimeMode.fromCliName(null));
    }
}
