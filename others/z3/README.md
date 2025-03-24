# Z3

## Installation

To install this framework, run:

```bash
python3 -m pip install z3-solver
```

## Usage

### Case 1 - System of 2 linear equations using `z3.solve`

Let's say we have a system of two linear equations:

$$
\begin{cases}
2x + y = 3 \\
x - y = 6
\end{cases}
$$

We can see that there are 2 variables `x` and `y` so we will first declare those vars as float number:

```python
import z3

x = z3.Real('x')
y = z3.Real('y')
```

Now we want to solve that system, we just need to add conditions separated by comma into `solve` function:

```python
z3.solve(
    2*x + y == 3,
    x - y == 6
)
```

Run the script and it will print the result for us:

![](images/system-with-two-linear-equations.png)

:::Full script
```python
import z3

x = z3.Real('x')
y = z3.Real('y')

z3.solve(
    2*x + y == 3,
    x - y == 6
)
```
:::

### Case 2 - System of 3 linear equations using `z3.Solver`

Let's say we have a system of three linear equations:

$$
\begin{cases}
\frac{1}{x} + \frac{1}{y} + \frac{1}{z} = 10 \\
\frac{2}{x} - \frac{1}{y} + \frac{3}{z} = 16 \\
\frac{1}{x} - \frac{2}{y} - \frac{1}{z} = -9
\end{cases}
$$

As we have done in [case 1](#case-1), let's define 3 variables:

```python
from z3 import *

x = Real('x')
y = Real('y')
z = Real('z')
```

Now instead of using `solve` function, we will use `Solver` class and use `Solver.add()` to add condition:

```python
from z3 import *

x = Real('x')
y = Real('y')
z = Real('z')

s = Solver()

s.add(1/x + 1/y + 1/z == 10)
s.add(2/x - 1/y + 3/z == 16)
s.add(1/x - 2/y - 1/z == -9)
s.add(x!=0, y!=0, z!=0)
```

To solve this system, we first need to check if condition is satisfied or not using `Solver.check()`:

```python
from z3 import *

x = Real('x')
y = Real('y')
z = Real('z')

s = Solver()

s.add(1/x + 1/y + 1/z == 10)
s.add(2/x - 1/y + 3/z == 16)
s.add(1/x - 2/y - 1/z == -9)
s.add(x!=0, y!=0, z!=0)

if s.check() == sat:
	pass
```

If it can be solved, we can get the result using `Solver.model()`:

```python
from z3 import *

x = Real('x')
y = Real('y')
z = Real('z')

s = Solver()

s.add(1/x + 1/y + 1/z == 10)
s.add(2/x - 1/y + 3/z == 16)
s.add(1/x - 2/y - 1/z == -9)
s.add(x!=0, y!=0, z!=0)

if s.check() == sat:
	res = s.model()
    x_val = res[x].as_fraction()
    y_val = res[y].as_fraction()
    z_val = res[z].as_fraction()
    print(f'x = {str(x_val)} = {float(x_val)}')
    print(f'y = {str(y_val)} = {float(y_val)}')
    print(f'z = {str(z_val)} = {float(z_val)}')
```

Run the script and we get the result:

![](images/system-with-three-linear-equations.png)

### Case 3 - Bit Comparation

With the problem as below:

```
Given a = 150, b = 36 and c = 92, find x with these equations:

((a >> 0) & 1) XOR  ((b >> 0) & 1) NOR  ((x >> 0) & 1) == ((c >> 0) & 1)
((a >> 1) & 1) OR   ((b >> 1) & 1) XNOR ((x >> 1) & 1) == ((c >> 1) & 1)
((a >> 2) & 1) NAND ((b >> 2) & 1) NOR  ((x >> 2) & 1) == ((c >> 2) & 1)
((a >> 3) & 1) NAND ((b >> 3) & 1) XNOR ((x >> 3) & 1) == ((c >> 3) & 1)
((a >> 4) & 1) OR   ((b >> 4) & 1) AND  ((x >> 4) & 1) == ((c >> 4) & 1)
((a >> 5) & 1) XNOR ((b >> 5) & 1) OR   ((x >> 5) & 1) == ((c >> 5) & 1)
((a >> 6) & 1) NAND ((b >> 6) & 1) XNOR ((x >> 6) & 1) == ((c >> 6) & 1)
((a >> 7) & 1) NOR  ((b >> 7) & 1) XOR  ((x >> 7) & 1) == ((c >> 7) & 1)
```

We know that we will need to work with bit for this case so let's define 4 variables using BitVec:

```python
from z3 import *

a = BitVecVal(150, 8)
b = BitVecVal(36, 8)
x = BitVec('x', 8)
c = BitVecVal(92, 8)
```

For convenience when doing with `Not` (NOR, XNOR and NAND), I will define several lambda functions:

```python
from z3 import *

a = BitVecVal(150, 8)
b = BitVecVal(36, 8)
x = BitVec('x', 8)
c = BitVecVal(92, 8)

XOR = lambda x, y: Xor(x, y)
XNOR = lambda x, y: Not(Xor(x, y))
AND = lambda x, y: And(x, y)
NAND = lambda x, y: Not(And(x, y))
OR = lambda x, y: Or(x, y)
NOR = lambda x, y: Not(Or(x, y))

def bit(n, var):
    return Extract(n, n, var) != 0
```

The function `bit` will be used to extract the bit of `var` at position `n`. Now let's add 8 conditions to solve:

```python
from z3 import *

a = BitVecVal(150, 8)
b = BitVecVal(36, 8)
x = BitVec('x', 8)
c = BitVecVal(92, 8)

XOR = lambda x, y: Xor(x, y)
XNOR = lambda x, y: Not(Xor(x, y))
AND = lambda x, y: And(x, y)
NAND = lambda x, y: Not(And(x, y))
OR = lambda x, y: Or(x, y)
NOR = lambda x, y: Not(Or(x, y))

def bit(n, var):
    return Extract(n, n, var) != 0
```




