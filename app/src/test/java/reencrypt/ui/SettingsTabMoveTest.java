package reencrypt.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;

/** Up/Down over a multi-selection: the plan the patterns table applies to one list. */
class SettingsTabMoveTest {

    private static final int UP = -1;
    private static final int DOWN = 1;

    private static String plan(List<Integer> indexes, int delta, int size) {
        return SettingsTab.planMove(indexes, delta, size).stream()
                .map(move -> move[0] + "->" + move[1])
                .collect(Collectors.joining(" "));
    }

    @Test
    void aBlockMovesAsAWhole() {
        assertEquals("1->0 2->1", plan(List.of(1, 2), UP, 5));
        assertEquals("3->4 2->3", plan(List.of(2, 3), DOWN, 5));
    }

    @Test
    void theEdgeBlocksTheWholeBlock() {
        // The top item cannot move, and the one behind it must not overtake it.
        assertEquals("0->0 1->1", plan(List.of(0, 1), UP, 5));
        assertEquals("4->4 3->3", plan(List.of(3, 4), DOWN, 5));
    }

    @Test
    void gapsCloseUpTowardsTheEdge() {
        // Row 1 is not selected, so row 2 takes it; row 0 has nowhere to go.
        assertEquals("0->0 2->1", plan(List.of(0, 2), UP, 5));
        assertEquals("4->4 2->3", plan(List.of(4, 2), DOWN, 5));
    }

    @Test
    void inputOrderDoesNotMatter() {
        assertEquals(plan(List.of(2, 4), UP, 5), plan(List.of(4, 2), UP, 5));
    }

    @Test
    void everythingSelectedStaysPut() {
        assertEquals("0->0 1->1 2->2", plan(List.of(0, 1, 2), UP, 3));
        assertEquals("2->2 1->1 0->0", plan(List.of(0, 1, 2), DOWN, 3));
    }
}
