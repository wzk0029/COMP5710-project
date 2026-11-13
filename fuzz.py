import os
import random
import traceback

import graphtaint
import parser
import scanner

ITERATIONS = 2000
random.seed(5710)


def random_value():
    values = [None, True, False, 0, 1, -1, 1.5, "", "a", "kind", "spec",
              "password", "user", "default", "http://x", "A" * 3000]
    return random.choice(values)


def random_key():
    keys = [None, 1, 1.5, True, "kind", "spec", "user", "password", "name", "key"]
    return random.choice(keys)


def random_data(depth=0):
    if depth > 3 or random.random() < 0.3:
        return random_value()
    if random.random() < 0.5:
        result = {}
        for i in range(random.randint(0, 4)):
            result[random_key()] = random_data(depth + 1)
        return result
    items = []
    for i in range(random.randint(0, 4)):
        items.append(random_data(depth + 1))
    return items


def random_dict():
    result = {}
    for i in range(random.randint(0, 4)):
        result[random_key()] = random_data(1)
    return result


def deep_data():
    data = "x"
    for i in range(1500):
        data = {"spec": data}
    return data


def random_or_deep():
    if random.random() < 0.05:
        return deep_data()
    return random_data()


def random_docs():
    docs = []
    for i in range(random.randint(0, 3)):
        docs.append(random.choice([random_dict(), random_dict(), None, [], random_data()]))
    return docs


def random_secret_dict():
    return {"password": ([random_value()], [random_value()], [random_value()])}


# (name, function, function that makes the arguments)
TESTS = [
    ("parser.keyMiner", parser.keyMiner,
     lambda: (random_or_deep(), random_value())),
    ("parser.getKeyRecursively", parser.getKeyRecursively,
     lambda: (random_dict(), [])),
    ("parser.getValuesRecursively", lambda d: list(parser.getValuesRecursively(d)),
     lambda: (random_or_deep(),)),
    ("parser.getValsFromKey", parser.getValsFromKey,
     lambda: (random_dict(), random_key(), [])),
    ("parser.getSingleDict4MultiDocs", parser.getSingleDict4MultiDocs,
     lambda: (random_docs(),)),
    ("parser.find_json_path_keys", parser.find_json_path_keys,
     lambda: (random_docs(),)),
    ("scanner.checkIfValidSecret", scanner.checkIfValidSecret,
     lambda: (random_value(),)),
    ("scanner.scanForSecrets", scanner.scanForSecrets,
     lambda: (random_dict(),)),
    ("scanner.getItemFromSecret", scanner.getItemFromSecret,
     lambda: (random_secret_dict(), random.choice([0, 1, 2]))),
    ("graphtaint.constructHelmString", graphtaint.constructHelmString,
     lambda: ((random_value(), random_value(), random_value()),)),
]

report = ["# Fuzzing report", "", "| Method | Bugs found |", "|---|---|"]
details = []
total_bugs = 0

for name, function, make_args in TESTS:
    bugs = {}
    for i in range(ITERATIONS):
        args = make_args()
        try:
            function(*args)
        except Exception as error:
            last_call = traceback.extract_tb(error.__traceback__)[-1]
            location = os.path.basename(last_call.filename) + ":" + str(last_call.lineno)
            bug_id = type(error).__name__ + " at " + location
            if bug_id not in bugs:
                bugs[bug_id] = (str(error)[:100], str(args)[:150])
    print(name, "->", len(bugs), "bug(s)")
    report.append("| " + name + " | " + str(len(bugs)) + " |")
    for bug_id, (message, example) in bugs.items():
        total_bugs += 1
        details.append("### " + name + ": " + bug_id)
        details.append("- Message: " + message.replace("`", "'"))
        details.append("- Example input: `" + example.replace("`", "'").replace("\n", " ") + "`")
        details.append("")

report.append("")
report.append("Total bugs: " + str(total_bugs))
report.append("")
text = "\n".join(report + details) + "\n"

with open("fuzz_report.md", "w", encoding="utf-8") as file:
    file.write(text)
print("\n" + text)

summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
if summary_file:
    with open(summary_file, "a", encoding="utf-8") as file:
        file.write(text)