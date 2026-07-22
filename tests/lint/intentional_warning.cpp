// Compiled only by `just lint-warning-gate-test`. The char index deliberately
// triggers -Wchar-subscripts so the test proves the project-wide -Werror policy.
int IntentionalLintWarningFixture(char index) {
  int values[1] = {0};
  return values[index];
}
