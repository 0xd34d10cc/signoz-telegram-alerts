package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/telebot.v3"
)

// KV is a set of key/value string pairs.
type KV map[string]string

// Data is the data passed to notification templates and webhook pushes.
//
// End-users should not be exposed to Go's type system, as this will confuse them and prevent
// simple things like simple equality checks to fail. Map everything to float64/string.
type Data struct {
	Receiver string `json:"receiver"`
	Status   string `json:"status"`
	Alerts   Alerts `json:"alerts"`

	GroupLabels       KV `json:"groupLabels"`
	CommonLabels      KV `json:"commonLabels"`
	CommonAnnotations KV `json:"commonAnnotations"`

	ExternalURL string `json:"externalURL"`
}

// Alert holds one alert for notification templates.
type Alert struct {
	Status       string    `json:"status"`
	Labels       KV        `json:"labels"`
	Annotations  KV        `json:"annotations"`
	StartsAt     time.Time `json:"startsAt"`
	EndsAt       time.Time `json:"endsAt"`
	GeneratorURL string    `json:"generatorURL"`
	Fingerprint  string    `json:"fingerprint"`
}

// Alerts is a list of Alert objects.
type Alerts []Alert

type Message struct {
	*Data

	// The protocol version.
	Version         string `json:"version"`
	GroupKey        string `json:"groupKey"`
	TruncatedAlerts uint64 `json:"truncatedAlerts"`
}

type AlertInfo struct {
	firing     bool
	lastUpdate time.Time
}

func formatAlert(b *strings.Builder, name string, firing bool, lastUpdate time.Time) {
	if !firing {
		b.WriteRune('✅')
	} else {
		b.WriteRune('❌')
	}
	b.WriteString(name)
	b.WriteRune(' ')
	b.WriteString(lastUpdate.Format(time.DateTime))
}

type AlertsState struct {
	m      sync.Mutex
	alerts map[string]AlertInfo
}

func (state *AlertsState) Clear(name string) bool {
	state.m.Lock()
	defer state.m.Unlock()

	_, ok := state.alerts[name]
	if !ok {
		return false
	}

	state.alerts[name] = AlertInfo{
		firing:     false,
		lastUpdate: time.Now(),
	}
	return true
}

func (state *AlertsState) Delete(name string) bool {
	state.m.Lock()
	defer state.m.Unlock()

	_, ok := state.alerts[name]
	if ok {
		delete(state.alerts, name)
	}
	return ok
}

func (state *AlertsState) Update(name string, firing bool, lastUpdate time.Time) bool {
	state.m.Lock()
	defer state.m.Unlock()

	prevStatus, ok := state.alerts[name]
	state.alerts[name] = AlertInfo{
		firing:     firing,
		lastUpdate: lastUpdate,
	}

	if !ok || prevStatus.firing != firing {
		return true
	}

	return false
}

func (state *AlertsState) Status() string {
	var b strings.Builder

	state.m.Lock()
	defer state.m.Unlock()
	for name, info := range state.alerts {
		formatAlert(&b, name, info.firing, info.lastUpdate)
		b.WriteRune('\n')
	}

	return b.String()
}

func main() {
	token, ok := os.LookupEnv("TELEGRAM_TOKEN")
	if !ok {
		log.Fatal("Set TELEGRAM_TOKEN environment variable")
	}

	addr, ok := os.LookupEnv("ADDR")
	if !ok {
		log.Fatal("Set ADDR environment variable")
	}

	c, ok := os.LookupEnv("CHAT_ID")
	if !ok {
		log.Fatal("Set CHAT_ID environment variable")
	}

	chatID, err := strconv.ParseInt(c, 10, 64)
	if err != nil {
		log.Fatalf("Invalid chat ID %v: %v\n", chatID, err)
	}

	pref := telebot.Settings{
		Token:  token,
		Poller: &telebot.LongPoller{Timeout: 10 * time.Second},
	}

	b, err := telebot.NewBot(pref)
	if err != nil {
		log.Fatal(err)
		return
	}

	state := AlertsState{
		m:      sync.Mutex{},
		alerts: map[string]AlertInfo{},
	}

	// restrictChat := middleware.Restrict(middleware.RestrictConfig{
	// 	Chats: []int64{chatID},
	// 	Out: func(c telebot.Context) error {
	// 		return c.Reply("Not allowed in this chat")
	// 	},
	// })

	b.Handle("/status", func(c telebot.Context) error {
		status := state.Status()
		if status == "" {
			return c.Reply("No alerts available")
		}

		return c.Reply(status)
	})

	b.Handle("/clear", func(c telebot.Context) error {
		name := strings.TrimPrefix(c.Message().Text, "/clear ")
		status := state.Clear(name)
		return c.Reply(fmt.Sprintf("Cleared %v: %v", name, status))
	})

	b.Handle("/delete", func(c telebot.Context) error {
		name := strings.TrimPrefix(c.Message().Text, "/clear ")
		status := state.Delete(name)
		return c.Reply(fmt.Sprintf("Deleted %v: %v", name, status))
	})

	b.Handle("/inspect", func(c telebot.Context) error {
		m, err := json.MarshalIndent(c.Message(), "", " ")
		if err != nil {
			log.Printf("Failed to marshal message: %v", err)
		}

		return c.Send(string(m))
	})

	go b.Start()

	chat, err := b.ChatByID(chatID)
	if err != nil {
		log.Fatalf("Failed to get chat: %v", err)
	}

	http.HandleFunc("/alert", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("Failed to read alert message: %v", err)
			// no reason to respond here
			return
		}

		log.Println("Received alert message: ", string(body))

		var message Message
		err = json.Unmarshal(body, &message)
		if err != nil {
			log.Printf("Failed to parse alert message: %v", err)
			// don't respond with error to avoid retrying
			return
		}

		for _, alert := range message.Alerts {
			firing := true
			if alert.Status == "resolved" {
				firing = false
			}

			lastUpdate := alert.StartsAt
			if !firing {
				lastUpdate = alert.EndsAt
			}

			name := alert.Labels["alertname"]
			if !state.Update(name, firing, lastUpdate) {
				continue
			}

			var update strings.Builder
			formatAlert(&update, name, firing, lastUpdate)
			summary, ok := alert.Annotations["summary"]
			if ok {
				update.WriteRune('\n')
				update.WriteString(summary)
			}

			_, err = b.Send(chat, update.String())
			if err != nil {
				log.Printf("Failed to send alert message: %v", err)
			}
		}

		w.WriteHeader(http.StatusOK)
	})

	log.Printf("Starting on %v", addr)
	err = http.ListenAndServe(addr, nil)
	if err != nil {
		log.Fatal(err)
	}
}
