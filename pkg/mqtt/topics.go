package mqtt

// CLI topic construction, in one place so the protocol can be changed in one
// edit rather than five.
const (
	cliInputSegment   = "/cli/"
	cliInputWildcard  = "/cli/#"
	cliResponseSuffix = "/cli/response"
)

// CLICommandTopic is the topic a CLI command is published to.
func CLICommandTopic(prefix, command string) string {
	return prefix + cliInputSegment + command
}

// CLIInputSubscription is the wildcard a device subscribes to for commands.
func CLIInputSubscription(prefix string) string {
	return prefix + cliInputWildcard
}

// CLIResponseTopic is the topic firmware publishes CLI responses to.
func CLIResponseTopic(prefix string) string {
	return prefix + cliResponseSuffix
}
