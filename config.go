package main

import (
	"fmt"
	"io/ioutil"
	"sync"

	"github.com/prometheus/common/log"
	yaml "gopkg.in/yaml.v2"
)

type Config struct {
	Devices map[string]DeviceConfig `yaml:"devices"`
}

type SafeConfig struct {
	sync.RWMutex
	C *Config
}

type DeviceConfig struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

func (sc *SafeConfig) ReloadConfig(configFile string) error {
	var c = &Config{}

	yamlFile, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Errorf("Error reading config file: %s", err)
		return err
	}
	if err := yaml.Unmarshal(yamlFile, c); err != nil {
		log.Errorf("Error parsing config file: %s", err)
		return err
	}

	sc.Lock()
	sc.C = c
	sc.Unlock()

	log.Infoln("Loaded config file")
	return nil
}

func (sc *SafeConfig) DeviceConfigForTarget(target string) (*DeviceConfig, error) {
	sc.Lock()
	defer sc.Unlock()
	if deviceConfig, ok := sc.C.Devices[target]; ok {
		return &DeviceConfig{
			Username: deviceConfig.Username,
			Password: deviceConfig.Password,
		}, nil
	}
	if deviceConfig, ok := sc.C.Devices["default"]; ok {
		return &DeviceConfig{
			Username: deviceConfig.Username,
			Password: deviceConfig.Password,
		}, nil
	}
	return &DeviceConfig{}, fmt.Errorf("no credentials found for target %s", target)
}
