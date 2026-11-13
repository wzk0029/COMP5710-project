# Fuzzing report

| Method | Bugs found |
|---|---|
| parser.keyMiner | 1 |
| parser.getKeyRecursively | 0 |
| parser.getValuesRecursively | 1 |
| parser.getValsFromKey | 0 |
| parser.getSingleDict4MultiDocs | 2 |
| parser.find_json_path_keys | 1 |
| scanner.checkIfValidSecret | 0 |
| scanner.scanForSecrets | 0 |
| scanner.getItemFromSecret | 0 |
| graphtaint.constructHelmString | 1 |

Total bugs: 6

### parser.keyMiner: RecursionError at parser.py:44
- Message: maximum recursion depth exceeded
- Example input: `({'spec': {'spec': {'spec': {'spec': {'spec': {'spec': {'spec': {'spec': {'spec': {'spec': {'spec': {'spec': {'spec': {'spec': {'spec': {'spec': {'spe`

### parser.getValuesRecursively: RecursionError at parser.py:83
- Message: maximum recursion depth exceeded
- Example input: `({'spec': {'spec': {'spec': {'spec': {'spec': {'spec': {'spec': {'spec': {'spec': {'spec': {'spec': {'spec': {'spec': {'spec': {'spec': {'spec': {'spe`

### parser.getSingleDict4MultiDocs: IndexError at parser.py:379
- Message: list index out of range
- Example input: `([[], []],)`

### parser.getSingleDict4MultiDocs: TypeError at parser.py:402
- Message: unsupported operand type(s) for +: 'NoneType' and 'str'
- Example input: `([{None: [[], {'user': {1.5: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`

### parser.find_json_path_keys: TypeError at parser.py:255
- Message: expected string or bytes-like object, got 'NoneType'
- Example input: `([[], {'password': [{}, [[True, 0, '', True], [], 1.5, ['AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`

### graphtaint.constructHelmString: TypeError at graphtaint.py:25
- Message: can only concatenate str (not "int") to str
- Example input: `((1, False, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`

