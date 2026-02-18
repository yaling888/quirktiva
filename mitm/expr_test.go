package mitm

import (
	"bytes"
	"strings"
	"testing"

	"github.com/expr-lang/expr"
)

func TestEnv_Assign(t *testing.T) {
	type args struct {
		json string
		expr string
	}
	tests := []struct {
		name       string
		args       args
		wantBool   bool
		wantObject map[string]any
	}{
		{
			name: "assign value",
			args: args{
				json: `{
					"name": "aa", 
					"value": [
						{"key": "p", "height": 199},
						{"key": "q", "height": 200}
					]
				}`,
				// use 'data.' prefix to access the environment variables, it can omit as string key.
				expr: ` let f = filter(data.value, .key != "q");
						let c = concat(f, [{"key": "r", "height": 201}]);
						Assign("data.value", c); Assign("data.name", "bb"); Assign("data.week", "Tue")`,
			},
			wantBool: true,
			wantObject: map[string]any{
				"name": "bb",
				"week": "Tue",
				"value": []map[string]any{
					{
						"key":    "p",
						"height": 199,
					},
					{
						"key":    "r",
						"height": 201,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := readJSONBody(strings.NewReader(tt.args.json), nil, "", false)
			if err != nil {
				t.Error(err)
			}

			program, err := expr.Compile(tt.args.expr, expr.Env(Env{}), expr.AsBool())
			if err != nil {
				t.Error(err)
			}
			rs, err := exprRun(program, data)
			if err != nil {
				t.Error(err)
			}

			if tt.wantBool != rs {
				t.Fatal("exprRun:", "expected", tt.wantBool, "actual", rs)
			}

			expected := &bytes.Buffer{}
			_ = writeJSONBody(expected, tt.wantObject, nil, false)

			actual := &bytes.Buffer{}
			_ = writeJSONBody(actual, data, nil, false)

			if actual.Len() == 0 || expected.String() != actual.String() {
				t.Fatal("Assign:", "expected", tt.wantObject, "actual", data)
			}
		})
	}
}

func TestEnv_Delete(t *testing.T) {
	type args struct {
		json string
		expr string
	}
	tests := []struct {
		name       string
		args       args
		wantBool   bool
		wantObject any
	}{
		{
			name: "delete by single key",
			args: args{
				json: `{
					"adBreakHeartbeatParams": "aa", 
					"adSlots": [
						{"key": "p", "height": 199},
						{"key": "q", "height": 200}
					],
					"playerAds": [
						{"key": "p", "height": 199},
						{"key": "q", "height": 200}
					]
				}`,
				expr: `Delete("adSlots")`,
			},
			wantBool: true,
			wantObject: map[string]any{
				"adBreakHeartbeatParams": "aa",
				"playerAds": []map[string]any{
					{
						"key":    "p",
						"height": 199,
					},
					{
						"key":    "q",
						"height": 200,
					},
				},
			},
		},
		{
			name: "delete by keys in json object",
			args: args{
				json: `{
					"adBreakHeartbeatParams": "aa", 
					"adSlots": [
						{"key": "p", "height": 199},
						{"key": "q", "height": 200}
					],
					"playerResponse": {
						"playerAds": [
							{"key": "p", "height": 199},
							{"key": "q", "height": 200}
						]
					}
				}`,
				expr: `Delete("data.adSlots;data.playerResponse.playerAds")`, // use ';' separate the multiple keys
			},
			wantBool: true,
			wantObject: map[string]any{
				"adBreakHeartbeatParams": "aa",
				"playerResponse":         map[string]any{},
			},
		},
		{
			name: "delete by keys in json array",
			args: args{
				json: `[{
					"adBreakHeartbeatParams": "aa", 
					"adSlots": [
						{"key": "p", "height": 199},
						{"key": "q", "height": 200}
					],
					"playerResponse": {
						"playerAds": [
							{"key": "p", "height": 199},
							{"key": "q", "height": 200}
						],
						"adPlacements": [
							{"service": "i", "alt": "abc"}
						]
					}
				}]`,
				expr: `Delete("playerResponse.playerAds;adBreakHeartbeatParams")`,
			},
			wantBool: true,
			wantObject: []map[string]any{
				{
					"adSlots": []map[string]any{
						{"key": "p", "height": 199},
						{"key": "q", "height": 200},
					},
					"playerResponse": map[string]any{
						"adPlacements": []map[string]any{
							{"service": "i", "alt": "abc"},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := readJSONBody(strings.NewReader(tt.args.json), nil, "", false)
			if err != nil {
				t.Error(err)
			}

			program, err := expr.Compile(tt.args.expr, expr.Env(Env{}), expr.AsBool())
			if err != nil {
				t.Error(err)
			}
			rs, err := exprRun(program, data)
			if err != nil {
				t.Error(err)
			}

			if tt.wantBool != rs {
				t.Fatal("exprRun:", "expected", tt.wantBool, "actual", rs)
			}

			expected := &bytes.Buffer{}
			_ = writeJSONBody(expected, tt.wantObject, nil, false)

			actual := &bytes.Buffer{}
			_ = writeJSONBody(actual, data, nil, false)

			if actual.Len() == 0 || expected.String() != actual.String() {
				t.Fatal("Assign:", "expected", tt.wantObject, "actual", data)
			}
		})
	}
}
