Import("env")

def run_python_script(source, target, env):
    env.Execute("python scripts/spiffs_tool.py") 

env.AddCustomTarget(
    name="RunPythonScript",
    dependencies=None,
    actions=[run_python_script],
    title="Extract Saved Passwords",
    description=None,
)