package mqtt

// CLI topic construction, in one place so the protocol can be changed in one
// edit rather than fourteen.
//
// Command input and command output live in separate topic spaces. A device
// subscribes to the input wildcard; if responses shared that space the broker
// would forward every response the device just published straight back to it.
// Over cellular that echo arrives as a URC too large for the modem line buffer.
const (
	cliInputSegment   = "/cli/"
	cliInputWildcard  = "/cli/#"
	cliResponseSuffix = "/cli_response"
)

// CLICommandTopic is the topic a CLI command is published to.
func CLICommandTopic(prefix, command string) string {
	return prefix + cliInputSegment + command
}

// CLIInputSubscription is the wildcard a device subscribes to for commands.
func CLIInputSubscription(prefix string) string {
	return prefix + cliInputWildcard
}

// CLIResponseTopic is the topic firmware publishes CLI responses to. Chosen so
// it cannot match CLIInputSubscription.
func CLIResponseTopic(prefix string) string {
	return prefix + cliResponseSuffix
}
