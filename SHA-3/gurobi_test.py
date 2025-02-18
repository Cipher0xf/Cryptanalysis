import gurobipy as gb

m = gb.Model()
x = m.addVar(vtype='B', name="x")
y = m.addVar(vtype='B', name="y")
z = m.addVar(vtype='B', name="z")
m.setObjective(x + y + 2 * z, gb.GRB.MAXIMIZE)
m.addConstr(x + 2 * y + 3 * z <= 4)
m.addConstr(x + y >= 1)
m.optimize()

print(f"Optimal objective value: {m.objVal}")
print(f"Solution values: x={x.X}, y={y.X}, z={z.X}")
