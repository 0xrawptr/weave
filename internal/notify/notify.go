package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/0xrawptr/weave/internal/config"
)

type BatchEvent struct {
	BatchID    string `json:"batch_id"`
	CampaignID string `json:"campaign_id"`
	Status     string `json:"status"`
	Message    string `json:"message"`
	Targets    int    `json:"targets"`
	Ports      string `json:"ports"`
	Completed  int    `json:"completed"`
	Failed     int    `json:"failed"`
	Duration   string `json:"duration"`
}

func Send(cfg config.NotifyConfig, event BatchEvent) {
	if !cfg.Enabled {
		return
	}
	if cfg.WebhookURL != "" {
		sendWebhook(cfg.WebhookURL, event)
	}
	if cfg.DingTalkToken != "" {
		sendDingTalk(cfg.DingTalkToken, event)
	}
	if cfg.FeishuURL != "" {
		sendFeishu(cfg.FeishuURL, event)
	}
	if cfg.WecomURL != "" {
		sendWecom(cfg.WecomURL, event)
	}
}

func sendWebhook(url string, event BatchEvent) {
	body, _ := json.Marshal(event)
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("notify: webhook failed: %v", err)
		return
	}
	resp.Body.Close()
}

func sendDingTalk(token string, event BatchEvent) {
	url := fmt.Sprintf("https://oapi.dingtalk.com/robot/send?access_token=%s", token)
	text := fmt.Sprintf("批次 %s %s\n目标: %d | 完成: %d 失败: %d | 耗时: %s",
		event.BatchID, event.Status, event.Targets, event.Completed, event.Failed, event.Duration)
	body, _ := json.Marshal(map[string]interface{}{
		"msgtype": "text",
		"text":    map[string]string{"content": text},
	})
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("notify: dingtalk failed: %v", err)
		return
	}
	resp.Body.Close()
}

func sendFeishu(url string, event BatchEvent) {
	text := fmt.Sprintf("批次 %s %s\n目标: %d | 完成: %d 失败: %d | 耗时: %s",
		event.BatchID, event.Status, event.Targets, event.Completed, event.Failed, event.Duration)
	body, _ := json.Marshal(map[string]interface{}{
		"msg_type": "text",
		"content":  map[string]string{"text": text},
	})
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("notify: feishu failed: %v", err)
		return
	}
	resp.Body.Close()
}

func sendWecom(url string, event BatchEvent) {
	text := fmt.Sprintf("批次 %s %s\n目标: %d | 完成: %d 失败: %d | 耗时: %s",
		event.BatchID, event.Status, event.Targets, event.Completed, event.Failed, event.Duration)
	body, _ := json.Marshal(map[string]interface{}{
		"msgtype": "text",
		"text":    map[string]string{"content": text},
	})
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("notify: wecom failed: %v", err)
		return
	}
	resp.Body.Close()
}
