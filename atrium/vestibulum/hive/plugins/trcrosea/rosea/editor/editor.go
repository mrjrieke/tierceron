package testr

import (
	"fmt"
	"io"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	tccore "github.com/trimble-oss/tierceron-core/v2/core"
	flowcore "github.com/trimble-oss/tierceron-core/v2/flow"
	"github.com/trimble-oss/tierceron/atrium/vestibulum/hive/plugins/trcrosea/hcore/flowutil"
	roseacore "github.com/trimble-oss/tierceron/atrium/vestibulum/hive/plugins/trcrosea/rosea/core"
	"golang.org/x/term"
)

// Rosé Pine Moon styles
var (
	baseStyle = lipgloss.NewStyle().Background(lipgloss.Color("#232136")).Foreground(lipgloss.Color("#e0def4"))
	roseStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#eb6f92"))
	pineStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#9ccfd8"))
	foamStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#c4a7e7")).
			Background(lipgloss.Color("#232136"))
	editedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#ebbcba")).
			Background(lipgloss.Color("#232136"))
	goldStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#f6c177"))
)

type RoseaEditorModel struct {
	title        string
	width        int      // terminal width
	lines        []string // Committed lines
	input        string   // Current input (multi-line)
	cursor       int      // Cursor position in input
	historyIndex int      // 0 = live input, 1 = last, 2 = second last, etc.
	draft        string   // Saved live input when entering history mode
	draftCursor  int

	// Authentication related fields
	showAuthPopup bool
	authInput     string
	authCursor    int
	authError     string
	popupMode     string // "token" or "confirm"
	editorStyle   lipgloss.Style

	scrollOffset int
	height       int
}

func lines(b *[]byte) []string {
	var lines []string
	start := 0

	for i, c := range *b {
		if c == '\n' {
			end := i
			if end > start && (*b)[end-1] == '\r' {
				end--
			}
			lines = append(lines, string((*b)[start:end]))
			start = i + 1
		}
	}

	if start < len(*b) {
		end := len(*b)
		if end > start && (*b)[end-1] == '\r' {
			end--
		}
		lines = append(lines, string((*b)[start:end]))
	}

	return lines
}

func InitRoseaEditor(title string, data *[]byte) *RoseaEditorModel {
	width, height, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		width = 80
		height = 24
	}

	return &RoseaEditorModel{
		title:        title,
		width:        width,
		height:       height,
		lines:        []string{},
		input:        strings.Join(lines(data), "\n"), // Initialize input with existing lines
		cursor:       0,
		historyIndex: 0,
		draft:        "",
		editorStyle:  baseStyle.Padding(1, 2).Width(width),
	}
}

func (m *RoseaEditorModel) Init() tea.Cmd {
	return nil
}

func (m *RoseaEditorModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tea.KeyMsg:
		if m.showAuthPopup {

			switch m.popupMode {
			case "token":
				switch msg.Type {
				case tea.KeyEsc:
					m.input = m.draft
					//					m.cursor = 0
					m.cursor = m.draftCursor
					m.draft = ""
					m.showAuthPopup = false
					m.authInput = ""
					m.authCursor = 0
					m.authError = ""
				case tea.KeyEnter:
					if len(m.authInput) == 0 {
						m.authError = "Token cannot be empty"
					} else {
						m.input = m.draft
						m.cursor = m.draftCursor
						m.lines = append(m.lines, m.input)

						roseaSeedFile, roseaMemFs := roseacore.GetRoseaMemFs()
						roseaMemFs.Remove(roseaSeedFile)

						entrySeedFileRWC, err := roseaMemFs.Create(roseaSeedFile)
						if err != nil {
							// Pop up error?
							return m, nil
						}
						roseaEditR := strings.NewReader(m.input)
						_, err = io.Copy(entrySeedFileRWC, roseaEditR)
						if err != nil {
							// Pop up error?
							return m, nil
						}

						// Write current editor content to roseaMemFs
						chatResponseMsg := tccore.CallChatQueryChan(flowutil.GetChatMsgHookCtx(),
							"rosea", // From rainier
							&tccore.TrcdbExchange{
								Flows:     []string{flowcore.ArgosSociiFlow.TableName()},                                                                         // Flows
								Query:     fmt.Sprintf("SELECT * FROM %s.%s WHERE argosIdentitasNomen='%s'", "%s", flowcore.ArgosSociiFlow.TableName(), m.title), // Query
								Operation: "SELECT",                                                                                                              // query operation
								ExecTrcsh: "/edit/save.trc.tmpl",
								Request: tccore.TrcdbRequest{
									Rows: [][]any{
										{roseaMemFs},
										{m.authInput},
									},
								},
							},
							flowutil.GetChatSenderChan(),
						)
						if chatResponseMsg.TrcdbExchange != nil && len(chatResponseMsg.TrcdbExchange.Response.Rows) > 0 {
							// entrySeedFs := chatResponseMsg.TrcdbExchange.Request.Rows[0][0].(trcshio.MemoryFileSystem)
							// Chewbacca: If errors, maybe post an error message to popup?
						}
						m.historyIndex = 0
						//m.cursor = 0
						m.draft = ""
						m.showAuthPopup = false
						m.authError = ""
					}
					return m, nil
				case tea.KeyBackspace:
					if m.authCursor > 0 && len(m.authInput) > 0 {
						m.authInput = m.authInput[:m.authCursor-1] + m.authInput[m.authCursor:]
						m.authCursor--
					}
				case tea.KeyLeft:
					if m.authCursor > 0 {
						m.authCursor--
					}
				case tea.KeyRight:
					if m.authCursor < len(m.authInput) {
						m.authCursor++
					}
				default:
					s := msg.String()
					if len(s) > 0 && msg.Type != tea.KeySpace {
						s = roseacore.SanitizePaste(s)
						// Accept multi-character paste
						if m.showAuthPopup {
							m.authInput = m.authInput[:m.authCursor] + s + m.authInput[m.authCursor:]
							m.authCursor += len(s)
						} else {
							m.input = m.input[:m.cursor] + s + m.input[m.cursor:]
							m.cursor += len(s)
						}
					} else if msg.Type == tea.KeySpace {
						if m.showAuthPopup {
							m.authInput = m.authInput[:m.authCursor] + " " + m.authInput[m.authCursor:]
							m.authCursor++
						} else {
							m.input = m.input[:m.cursor] + " " + m.input[m.cursor:]
							m.cursor++
						}
					}
				}
				return m, nil
			case "confirm":
				switch msg.Type {
				case tea.KeyEnter:
					// Handle confirmation (proceed)
					m.showAuthPopup = false
					// ...do the action...
				case tea.KeyEsc:
					// Cancel
					m.showAuthPopup = false
				}
				return m, nil
			}
		}
		switch msg.Type {
		case tea.KeyCtrlC:
			return m, tea.Quit
		case tea.KeyEsc:
			return roseacore.GetRoseaNavigationCtx(), nil

		case tea.KeyCtrlS: // Submit on Ctrl+S
			m.draft = m.input
			m.draftCursor = m.cursor
			m.input = ""
			m.cursor = 0
			m.scrollOffset = 0
			m.showAuthPopup = true // <-- Add this line to trigger the popup
			m.popupMode = "token"
			// Optionally, reset popup fields:
			m.authInput = ""
			m.input = ""
			m.authCursor = 0
			m.authError = ""
			// TODO: figure out how to handle and save...
			// m.lines = append(m.lines, m.input)
			// m.input = ""
			// m.cursor = 0
			// m.historyIndex = 0
			// m.draft = ""

			return m, nil

		case tea.KeyEnter:
			// Insert newline at cursor
			m.input = m.input[:m.cursor] + "\n" + m.input[m.cursor:]
			m.cursor++
			return m, nil

		case tea.KeyBackspace:
			if m.cursor > 0 && len(m.input) > 0 {
				m.input = m.input[:m.cursor-1] + m.input[m.cursor:]
				m.cursor--
			}
			return m, nil

		case tea.KeyLeft:
			if m.cursor > 0 {
				m.cursor--
			}
			return m, nil

		case tea.KeyRight:
			if m.cursor < len(m.input) {
				m.cursor++
			}
			return m, nil

		case tea.KeyUp:
			visibleHeight := m.height - 4
			row, col := cursorRowCol(m.input, m.cursor)

			if row < m.scrollOffset {
				m.scrollOffset = row
			} else if row >= m.scrollOffset+visibleHeight {
				m.scrollOffset = row - visibleHeight + 1
			}
			if row > 0 {
				prevLineStart := nthLineStart(m.input, row-1)
				prevLineLen := lineLenAt(m.input, row-1)
				m.cursor = prevLineStart + min(col, prevLineLen)
			}
			return m, nil

		case tea.KeyDown:
			visibleHeight := m.height - 4
			row, col := cursorRowCol(m.input, m.cursor)

			if row < m.scrollOffset {
				m.scrollOffset = row
			} else if row >= m.scrollOffset+visibleHeight {
				m.scrollOffset = row - visibleHeight + 1
			}

			lineCount := strings.Count(m.input, "\n") + 1
			if row < lineCount-1 {
				nextLineStart := nthLineStart(m.input, row+1)
				nextLineLen := lineLenAt(m.input, row+1)
				m.cursor = nextLineStart + min(col, nextLineLen)
			}
			return m, nil

		default:
			s := msg.String()
			if len(s) > 0 && msg.Type != tea.KeySpace {
				s = roseacore.SanitizePaste(s)
				// Accept multi-character paste
				if m.showAuthPopup {
					m.authInput = m.authInput[:m.authCursor] + s + m.authInput[m.authCursor:]
					m.authCursor += len(s)
				} else {
					m.input = m.input[:m.cursor] + s + m.input[m.cursor:]
					m.cursor += len(s)
				}
			} else if msg.Type == tea.KeySpace {
				if m.showAuthPopup {
					m.authInput = m.authInput[:m.authCursor] + " " + m.authInput[m.authCursor:]
					m.authCursor++
				} else {
					m.input = m.input[:m.cursor] + " " + m.input[m.cursor:]
					m.cursor++
				}
			}
		}
	}

	return m, nil
}

// Helper functions for multi-line cursor movement
func cursorRowCol(s string, cursor int) (row, col int) {
	row = strings.Count(s[:cursor], "\n")
	lastNL := strings.LastIndex(s[:cursor], "\n")
	if lastNL == -1 {
		col = cursor
	} else {
		col = cursor - lastNL - 1
	}
	return
}

func nthLineStart(s string, n int) int {
	if n == 0 {
		return 0
	}
	i := 0
	for l := 0; l < n; l++ {
		j := strings.IndexByte(s[i:], '\n')
		if j == -1 {
			return len(s)
		}
		i += j + 1
	}
	return i
}

func lineLenAt(s string, n int) int {
	start := nthLineStart(s, n)
	end := strings.IndexByte(s[start:], '\n')
	if end == -1 {
		return len(s) - start
	}
	return end
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (m *RoseaEditorModel) View() string {
	var b strings.Builder

	b.WriteString(roseStyle.Render("Roséa Multi-line Editor — Ctrl+S to save, ESC to navigate"))
	b.WriteString("\n")

	for _, line := range m.lines {
		b.WriteString(pineStyle.Render(line) + "\n")
	}

	// Render input with cursor
	lines := strings.Split(m.input, "\n")
	visibleHeight := m.height - 4
	start := m.scrollOffset
	end := min(len(lines), start+visibleHeight)

	row, col := cursorRowCol(m.input, m.cursor)
	for i := start; i < end; i++ {
		line := lines[i]
		if i > start {
			b.WriteString("\n")
		}
		if i == row {
			var orig string
			if i < len(m.lines) {
				orig = m.lines[i]
			}
			split := 0
			maxCmp := min(len(line), len(orig))
			for split < maxCmp && line[split] == orig[split] {
				split++
			}
			left := foamStyle.Render(line[:split])
			changed := editedStyle.Render(line[split:])
			cursor := goldStyle.Render("|")
			// Place cursor at the right spot
			if col <= split {
				// Cursor in unchanged part
				b.WriteString(foamStyle.Render(line[:col]))
				b.WriteString(cursor)
				b.WriteString(foamStyle.Render(line[col:split]))
				b.WriteString(changed)
			} else {
				// Cursor in changed part
				b.WriteString(left)
				b.WriteString(editedStyle.Render(line[split:col]))
				b.WriteString(cursor)
				b.WriteString(editedStyle.Render(line[col:]))
			}
		} else {
			b.WriteString(foamStyle.Render(line))
		}
	}

	if m.showAuthPopup {
		var popupContent string
		switch m.popupMode {
		case "token":
			popupContent = "Enter authentication token:\n\n" +
				m.authInput[:m.authCursor] + goldStyle.Render("|") + m.authInput[m.authCursor:] +
				"\n\n" + m.authError + "\n\n[Enter=Submit, Esc=Cancel]"
		case "confirm":
			popupContent = "Are you sure you want to proceed?\n\n[Enter=Yes, Esc=Cancel]"
		}
		popup := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			Padding(1, 2).
			Width(40).
			Align(lipgloss.Center).
			Render(popupContent)
		// Overlay the popup (simple version)
		b.WriteString("\n\n" + popup)
	}

	return m.editorStyle.Width(m.width).Render(b.String())
}

// func main() {
// 	if err := tea.NewProgram(initialModel(nil)).Start(); err != nil {
// 		fmt.Println("Error:", err)
// 		os.Exit(1)
// 	}
// }
