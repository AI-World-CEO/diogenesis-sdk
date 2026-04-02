"""Voltage drop propagation between connected modules.

When one module's voltage drops, connected modules feel a fraction
of the drop. Connection = one module imports/calls another.
"""


class VoltagePropagation:
    """Propagate voltage drops through module connection graph."""

    def __init__(self, propagation_factor: float = 0.3):
        self.connections: dict = {}    # module -> set of connected modules
        self.propagation_factor = propagation_factor

    def learn_connections(self, events: list) -> None:
        """Build connection graph from event patterns.

        - Import events: caller module -> imported module = connection
        - File events: modules that access the same file = shared resource
        """
        # Import-based connections
        for event in events:
            if event.get("type") != "import":
                continue
            caller = event.get("caller_file", "")
            if not caller or caller == "unknown":
                continue
            import os
            caller_mod = os.path.splitext(os.path.basename(caller))[0]
            imported_mod = event.get("detail", {}).get("module", "")
            if not imported_mod or caller_mod == imported_mod:
                continue
            # Take top-level module name
            top = imported_mod.split(".")[0]
            self.connections.setdefault(caller_mod, set()).add(top)
            self.connections.setdefault(top, set()).add(caller_mod)

        # File-based shared resource connections
        file_users = {}  # filepath -> set of modules
        for event in events:
            if event.get("type") != "file":
                continue
            caller = event.get("caller_file", "")
            if not caller or caller == "unknown":
                continue
            import os
            caller_mod = os.path.splitext(os.path.basename(caller))[0]
            path = event.get("detail", {}).get("path", "")
            if path:
                file_users.setdefault(path, set()).add(caller_mod)

        for path, users in file_users.items():
            if len(users) > 1:
                user_list = list(users)
                for i, a in enumerate(user_list):
                    for b in user_list[i + 1:]:
                        self.connections.setdefault(a, set()).add(b)
                        self.connections.setdefault(b, set()).add(a)

    def propagate(self, voltage_field, dropped_module: str, drop_amount: float) -> list:
        """Propagate partial voltage drop to connected modules.

        Returns list of affected modules with their drop amounts.
        """
        affected = []
        neighbors = self.connections.get(dropped_module, set())
        propagated_drop = drop_amount * self.propagation_factor

        if propagated_drop < 0.001:
            return affected

        for neighbor in neighbors:
            mv = voltage_field.modules.get(neighbor)
            if mv is None:
                continue
            old_v = mv.voltage
            mv.drop_voltage(propagated_drop)
            affected.append({
                "module": neighbor,
                "from": round(old_v, 4),
                "to": round(mv.voltage, 4),
                "propagated_drop": round(propagated_drop, 4),
                "source": dropped_module,
            })

        return affected

    def get_connection_graph(self) -> dict:
        """Return {module: [connected_modules]} for visualization."""
        return {mod: sorted(conns) for mod, conns in self.connections.items()}
