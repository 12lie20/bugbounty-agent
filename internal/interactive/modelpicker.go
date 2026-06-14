package interactive

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/redteam/bugbounty-agent/internal/models"
)

// PromptForAPIKey asks for the opencode API key if it is not already set,
// then writes it to a .env file in the current working directory.
func PromptForAPIKey() (string, error) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter your opencode.ai API key: ")
	key, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read api key: %w", err)
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return "", fmt.Errorf("api key cannot be empty")
	}

	if err := os.WriteFile(".env", []byte("BB_AGENT_LLM_API_KEY="+key+"\n"), 0600); err != nil {
		return "", fmt.Errorf("failed to write .env: %w", err)
	}

	return key, nil
}

// PickModel shows the interactive model picker and returns the selected model.
func PickModel() models.OpencodeModel {
	fmt.Println("\nSelect an opencode.ai Go model:")
	fmt.Println(strings.Repeat("-", 50))
	for i, m := range models.OpencodeModels {
		fmt.Printf("[%2d] %-20s (%s)\n", i+1, m.DisplayName, m.APIType)
	}
	fmt.Println(strings.Repeat("-", 50))

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("Choice: ")
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Failed to read choice, please try again.")
			continue
		}
		input = strings.TrimSpace(input)
		idx, err := strconv.Atoi(input)
		if err != nil || idx < 1 || idx > len(models.OpencodeModels) {
			fmt.Printf("Invalid choice. Enter a number between 1 and %d.\n", len(models.OpencodeModels))
			continue
		}
		return models.OpencodeModels[idx-1]
	}
}
