package analysis

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
)

type FailureSeveritySummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
}

var outputFormats = map[string]func(*Analysis) ([]byte, error){
	"json": (*Analysis).jsonOutput,
	"text": (*Analysis).textOutput,
}

func getOutputFormats() []string {
	formats := make([]string, 0, len(outputFormats))
	for format := range outputFormats {
		formats = append(formats, format)
	}
	return formats
}

func (a *Analysis) PrintOutput(format string) ([]byte, error) {
	outputFunc, ok := outputFormats[format]
	if !ok {
		return nil, fmt.Errorf("unsupported output format: %s. Available format %s", format, strings.Join(getOutputFormats(), ","))
	}
	return outputFunc(a)
}

func (a *Analysis) jsonOutput() ([]byte, error) {
	var problems int
	var status AnalysisStatus
	var summary FailureSeveritySummary
	for _, result := range a.Results {
		problems += len(result.Error)
		for _, f := range result.Error {
			switch f.Severity {
			case common.SeverityCritical:
				summary.Critical++
			case common.SeverityHigh:
				summary.High++
			case common.SeverityMedium:
				summary.Medium++
			case common.SeverityLow:
				summary.Low++
			default:
				summary.Unknown++
			}
		}
	}
	if problems > 0 {
		status = StateProblemDetected
	} else {
		status = StateOK
	}

	result := JsonOutput{
		Provider: a.AnalysisAIProvider,
		Problems: problems,
		Results:  a.Results,
		Errors:   a.Errors,
		Status:   status,
		Summary:  summary,
	}
	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("error marshalling json: %v", err)
	}
	return output, nil
}

func (a *Analysis) PrintStats() []byte {
	var output strings.Builder

	output.WriteString(color.YellowString("The stats mode allows for debugging and understanding the time taken by an analysis by displaying the statistics of each analyzer.\n"))

	for _, stat := range a.Stats {
		output.WriteString(fmt.Sprintf("- Analyzer %s took %s \n", color.YellowString(stat.Analyzer), stat.DurationTime))
	}

	return []byte(output.String())
}

func (a *Analysis) textOutput() ([]byte, error) {
	var output strings.Builder

	// Print the AI provider used for this analysis (if explain was enabled).
	if a.Explain {
		output.WriteString(fmt.Sprintf("AI Provider: %s\n", color.YellowString(a.AnalysisAIProvider)))
	} else {
		output.WriteString(fmt.Sprintf("AI Provider: %s\n", color.YellowString("AI not used; --explain not set")))
	}

	if len(a.Errors) != 0 {
		output.WriteString("\n")
		output.WriteString(color.YellowString("Warnings : \n"))
		for _, aerror := range a.Errors {
			output.WriteString(fmt.Sprintf("- %s\n", color.YellowString(aerror)))
		}
	}
	output.WriteString("\n")
	if len(a.Results) == 0 {
		output.WriteString(color.GreenString("No problems detected\n"))
		return []byte(output.String()), nil
	}
	for n, result := range a.Results {
		output.WriteString(fmt.Sprintf("%s: %s %s(%s)\n", color.CyanString("%d", n),
			color.HiYellowString(result.Kind),
			color.YellowString(result.Name),
			color.CyanString(result.ParentObject)))
		for _, err := range result.Error {
			severityTag := severityTagString(err.Severity)
			if severityTag != "" {
				fmt.Fprintf(&output, "- %s %s %s\n", severityTag, color.RedString("Error:"), color.RedString(err.Text))
			} else {
				fmt.Fprintf(&output, "- %s %s\n", color.RedString("Error:"), color.RedString(err.Text))
			}
			if err.KubernetesDoc != "" {
				output.WriteString(fmt.Sprintf("  %s %s\n", color.RedString("Kubernetes Doc:"), color.RedString(err.KubernetesDoc)))
			}
			if err.Remediation != nil {
				switch err.Remediation.Type {
				case common.RemediationTypeCommand:
					fmt.Fprintf(&output, "  Remediation: %s\n", err.Remediation.Command)
					fmt.Fprintf(&output, "  Risk: %s\n", err.Remediation.Risk)
				case common.RemediationTypeInvestigation:
					output.WriteString("  Investigation steps:\n")
					for _, step := range err.Remediation.Steps {
						fmt.Fprintf(&output, "  - %s\n", step)
					}
				}
			}
		}
		output.WriteString(color.GreenString(result.Details + "\n"))
	}
	return []byte(output.String()), nil
}

func severityTagString(s common.Severity) string {
	switch s {
	case common.SeverityCritical:
		return color.New(color.FgRed, color.Bold).Sprint("[CRITICAL]")
	case common.SeverityHigh:
		return color.YellowString("[HIGH]")
	case common.SeverityMedium:
		return color.CyanString("[MEDIUM]")
	case common.SeverityLow:
		return color.WhiteString("[LOW]")
	default:
		return ""
	}
}
