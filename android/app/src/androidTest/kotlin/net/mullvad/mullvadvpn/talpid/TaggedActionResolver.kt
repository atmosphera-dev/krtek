package net.mullvad.mullvadvpn.talpid

/** Resolve ownership before acting. Ambiguous wrappers never authorize a guessed tap. */
internal object TaggedActionResolver {
    fun <T : Any> resolve(
        tagged: T,
        children: (T) -> List<T>,
        parent: (T) -> T?,
        isClickable: (T) -> Boolean,
        isToggleable: (T) -> Boolean = { false },
        describe: (T) -> String,
    ): T {
        val descendants =
            descendants(tagged, children).filter { isClickable(it) || isToggleable(it) }.toList()
        return when {
            isClickable(tagged) -> tagged
            descendants.size == 1 -> descendants.single()
            descendants.isNotEmpty() ->
                throw AssertionError(
                    "Ambiguous tagged action: tagged=${describe(tagged)}, " +
                        "candidates=${descendants.joinToString { describe(it) }}"
                )
            else ->
                generateSequence(parent(tagged), parent).firstOrNull(isClickable)
                    ?: throw AssertionError("Missing tagged action: tagged=${describe(tagged)}")
        }
    }

    private fun <T> descendants(node: T, children: (T) -> List<T>): Sequence<T> =
        children(node).asSequence().flatMap { sequenceOf(it) + descendants(it, children) }
}
