// region FUNC_agentClient [DOMAIN(9): Security; CONCEPT(7): SSHAgent; TECH(8): x/crypto/ssh/agent]
// @purpose Bridge the OS ssh-agent (SSH_AUTH_SOCK) into x/crypto/ssh so the "agent" auth_type can
//
//	sign challenges without the VM Pulse server ever holding a private key.
//
// @io (conn net.Conn) -> agent.Agent
// @complexity 3
// endregion FUNC_agentClient
// STRUCTURE: ▶ ┌unix sock conn┐ → agent.NewClient → ⎷ agent.Agent
package ssh

import (
	"net"

	"golang.org/x/crypto/ssh/agent"
)

func agentClient(conn net.Conn) agent.Agent {
	return agent.NewClient(conn)
}
