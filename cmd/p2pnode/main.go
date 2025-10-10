// cmd/p2pnode/main.go
package main

import (
        "bufio"
        "fmt"
        "log"
        "os"
        "strings"
        "time"
        "explosive/internal/p2p"
)

func main() {
        fmt.Println("✩️ Welcome to Explosive P2P Node – Mainnet Ready 🚀")

        reader := bufio.NewReader(os.Stdin)
        fmt.Println("🌍 Choose your language / Choisissez votre langue:")
        fmt.Println("1. English")
        fmt.Println("2. Français")
        fmt.Print("> ")
        langInput, _ := reader.ReadString('\n')
        langInput = strings.TrimSpace(langInput)

        lang := "EN"
        if langInput == "2" {
                lang = "FR"
        }

        // Prompt miner ID and sacred words
        fmt.Print("🆔 Enter your Miner ID (starts with 'explo'): ")
        minerID, _ := reader.ReadString('\n')
        minerID = strings.TrimSpace(minerID)

        words := make([]string, 4)
        for i := 0; i < 4; i++ {
                fmt.Printf("🔑 Enter sacred word %d: ", i+1)
                w, _ := reader.ReadString('\n')
                words[i] = strings.TrimSpace(w)
        }

        // Automatically derive listening address
        port := p2p.DeriveListenPort(minerID, words) // returns string like "4001"
        listenAddr := fmt.Sprintf("0.0.0.0:%s", port)
        fmt.Printf("🔌 Your node will listen on %s\n", listenAddr)

        // Create new P2P node
        node := p2p.NewNode(listenAddr, "explosive-mainnet", "ExplosiveNode/1.0")
        if err := node.Start(); err != nil {
                log.Fatalf("❌ Failed to start node: %v", err)
        }

        fmt.Printf("🚀 Node started successfully on %s\n", listenAddr)
        fmt.Printf("📡 Protocol version: %d\n", node.ProtocolVersion())

mainLoop:
        for {
                if lang == "EN" {
                        fmt.Println("\n🔧 Choose action:")
                        fmt.Println("1. Connect to peer")
                        fmt.Println("2. List peers")
                        fmt.Println("3. Broadcast ping")
                        fmt.Println("4. Exit")
                        fmt.Print("> ")
                } else {
                        fmt.Println("\n🔧 Choisissez une action :")
                        fmt.Println("1. Se connecter à un pair")
                        fmt.Println("2. Lister les pairs")
                        fmt.Println("3. Envoyer un ping à tous")
                        fmt.Println("4. Quitter")
                        fmt.Print("> ")
                }

                input, _ := reader.ReadString('\n')
                input = strings.TrimSpace(input)

                switch input {
                case "1":
                        fmt.Print("🔗 Enter peer address (ip:port): ")
                        addr, _ := reader.ReadString('\n')
                        addr = strings.TrimSpace(addr)
                        if addr != "" {
                                if peer, err := node.Connect(addr); err != nil {
                                        fmt.Printf("❌ Failed to connect: %v\n", err)
                                } else {
                                        fmt.Printf("✅ Connected to peer %s\n", peer.Addr())
                                }
                        }
                case "2":
                        peers := node.ListPeers()
                        if len(peers) == 0 {
                                fmt.Println("📭 No connected peers.")
                        } else {
                                fmt.Println("🤝 Connected peers:")
                                for id, addr := range peers {
                                        fmt.Printf("- %s: %s\n", id, addr)
                                }
                        }
                case "3":
                        ping := p2p.PingPayload{Nonce: time.Now().UnixNano()}
                        env, _ := p2p.NewEnvelopeFromPayload(node.ProtocolVersion(), p2p.MsgTypePing, ping)
                        node.Broadcast(env)
                        fmt.Println("📡 Ping broadcasted to all peers!")
                case "4":
                        break mainLoop
                default:
                        fmt.Println("⚠️ Invalid choice. Please try again.")
                }
        }

        fmt.Println("🛑 Shutting down node...")
        node.Stop()
        fmt.Println("✅ Node stopped. Goodbye!")
}
