package dev.alaka.property;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import dev.alaka.core.RuntimeMode;
import java.util.Arrays;
import net.jqwik.api.Assume;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;

/** jqwik properties of {@link RuntimeMode} CLI-name parsing. */
class RuntimeModeProperties {

    @Property
    void cliNameRoundTripsThroughTheParser(@ForAll RuntimeMode mode) {
        assertThat(RuntimeMode.fromCliName(mode.cliName())).isSameAs(mode);
    }

    @Property
    void anyStringThatIsNotACliNameIsRejected(@ForAll String value) {
        Assume.that(Arrays.stream(RuntimeMode.values())
                .noneMatch(mode -> mode.cliName().equals(value)));

        assertThatIllegalArgumentException()
                .isThrownBy(() -> RuntimeMode.fromCliName(value));
    }
}
