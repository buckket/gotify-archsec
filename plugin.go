package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/gotify/plugin-api"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"
)

const FeedURL string = "https://security.archlinux.org/advisory/feed.atom"

type Feed struct {
	XMLName xml.Name   `xml:"feed"`
	Entries EntrySlice `xml:"entry"`
}

type Entry struct {
	XMLName   xml.Name   `xml:"entry"`
	Title     string     `xml:"title"`
	Link      LinkStruct `xml:"link"`
	Published time.Time  `xml:"published"`
}

type LinkStruct struct {
	XMLName  xml.Name `xml:"link"`
	Location string   `xml:"href,attr"`
}

type Storage struct {
	LastPublished time.Time `json:"last_published"`
}

type Config struct {
	RefreshInterval int `yaml:"refresh_interval"`
}

type EntrySlice []Entry

func (es *EntrySlice) Len() int           { return len(*es) }
func (es *EntrySlice) Less(i, j int) bool { return (*es)[i].Published.Before((*es)[j].Published) }
func (es *EntrySlice) Swap(i, j int)      { (*es)[i], (*es)[j] = (*es)[j], (*es)[i] }

func GetGotifyPluginInfo() plugin.Info {
	return plugin.Info{
		ModulePath:  "github.com/buckket/gotify-archsec",
		Version:     "1.0.0",
		Author:      "buckket",
		Website:     "https://github.com/buckket/gotify-archsec",
		Description: "Poll Arch Linux Security Feed for new advisories",
		License:     "GPLv3+",
		Name:        "archsec",
	}
}

type ArchSec struct {
	msgHandler     plugin.MessageHandler
	storageHandler plugin.StorageHandler
	config         *Config
	enabled        bool
	stop           chan struct{}
	wg             *sync.WaitGroup
	ticker         *time.Ticker
}

func (c *ArchSec) FetchFeed() {
	var storage Storage
	storageBytes, err := c.storageHandler.Load()
	if err != nil {
		log.Printf("could not load storage data: %v", err)
	}
	err = json.Unmarshal(storageBytes, &storage)
	if err != nil {
		log.Printf("could not parse storage data: %v", err)
	}

	resp, err := http.Get(FeedURL)
	if err != nil {
		log.Printf("error while fetching feed: %v", err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	var feed Feed
	err = xml.Unmarshal(body, &feed)
	if err != nil {
		log.Printf("error while parsing feed: %v", err)
		return
	}

	sort.Sort(&feed.Entries)
	for _, entry := range feed.Entries {
		if entry.Published.After(storage.LastPublished) {
			storage.LastPublished = entry.Published
			_ = c.msgHandler.SendMessage(plugin.Message{
				Title:   entry.Title,
				Message: entry.Link.Location,
			})
		}
	}

	newStorage, err := json.Marshal(storage)
	if err != nil {
		log.Printf("could not marshal storage data: %v", err)
		return
	}
	err = c.storageHandler.Save(newStorage)
	if err != nil {
		log.Printf("could not save storage data: %v", err)
	}
}

func (c *ArchSec) Enable() error {
	if c.enabled {
		return fmt.Errorf("plugin already enabled")
	}

	c.wg = &sync.WaitGroup{}
	c.stop = make(chan struct{})
	c.ticker = time.NewTicker(time.Duration(c.config.RefreshInterval) * time.Second)
	c.enabled = true

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		for {
			select {
			case <-c.stop:
				return
			case <-c.ticker.C:
				c.FetchFeed()
			}
		}
	}()
	return nil
}

func (c *ArchSec) Disable() error {
	if c.enabled {
		c.enabled = false
		c.ticker.Stop()
		close(c.stop)
		c.wg.Wait()
	} else {
		return fmt.Errorf("plugin already disabled")
	}
	return nil
}

func (c *ArchSec) GetDisplay(location *url.URL) string {
	var storage Storage

	storageBytes, err := c.storageHandler.Load()
	if err != nil {
		return fmt.Sprintf("Could not load storage data: %v", err)
	}

	err = json.Unmarshal(storageBytes, &storage)
	if err != nil {
		return fmt.Sprintf("Could not parse storage data: %v (%v)", err, storageBytes)
	}

	if storage.LastPublished.IsZero() {
		return fmt.Sprintf("Feed has not been updated as of yet")
	} else {
		return fmt.Sprintf("Last entry was published at %s", storage.LastPublished)
	}
}

func (c *ArchSec) SetStorageHandler(h plugin.StorageHandler) {
	c.storageHandler = h
}

func (c *ArchSec) SetMessageHandler(h plugin.MessageHandler) {
	c.msgHandler = h
}

func (c *ArchSec) DefaultConfig() interface{} {
	return &Config{
		RefreshInterval: 60,
	}
}

func (c *ArchSec) ValidateAndSetConfig(config interface{}) error {
	c.config = config.(*Config)
	return nil
}

func NewGotifyPluginInstance(ctx plugin.UserContext) plugin.Plugin {
	return &ArchSec{}
}

func main() {
	panic("this should be built as go plugin")
}
