"""
Tkinter user interface for the network topology editor.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Callable, Dict, Iterable, Optional, Tuple

from data.io_manager import TopologyIO
from logic.topology_manager import TopologyManager

DEVICE_TYPES = ["Router", "Switch", "Server", "PC"]
LINK_TYPES = ["wired", "wireless"]


class DeviceDialog(simpledialog.Dialog):
    """Modal dialog to capture device properties."""

    def __init__(
        self,
        parent: tk.Misc,
        title: str,
        *,
        initial: Optional[Dict[str, str]] = None,
    ) -> None:
        self.initial = initial or {}
        self.result_data: Optional[Dict[str, str]] = None
        super().__init__(parent, title=title)

    def body(self, master: tk.Misc) -> tk.Widget:
        ttk.Label(master, text="Device type:").grid(row=0, column=0, sticky="w")
        ttk.Label(master, text="Hostname:").grid(row=1, column=0, sticky="w")
        ttk.Label(master, text="IP address:").grid(row=2, column=0, sticky="w")

        self.device_type_var = tk.StringVar(
            value=self.initial.get("device_type", DEVICE_TYPES[0])
        )
        self.hostname_var = tk.StringVar(value=self.initial.get("hostname", ""))
        self.ip_var = tk.StringVar(value=self.initial.get("ip_address", ""))

        self.device_type_combo = ttk.Combobox(
            master, textvariable=self.device_type_var, values=DEVICE_TYPES, state="readonly"
        )
        self.device_type_combo.grid(row=0, column=1, pady=2, sticky="ew")

        self.hostname_entry = ttk.Entry(master, textvariable=self.hostname_var)
        self.hostname_entry.grid(row=1, column=1, pady=2, sticky="ew")

        self.ip_entry = ttk.Entry(master, textvariable=self.ip_var)
        self.ip_entry.grid(row=2, column=1, pady=2, sticky="ew")

        master.grid_columnconfigure(1, weight=1)
        return self.hostname_entry

    def validate(self) -> bool:
        hostname = self.hostname_var.get().strip()
        ip_address = self.ip_var.get().strip()
        if not hostname:
            messagebox.showerror("Validation error", "Hostname cannot be empty.")
            return False
        if not ip_address:
            messagebox.showerror("Validation error", "IP address cannot be empty.")
            return False
        return True

    def apply(self) -> None:
        self.result_data = {
            "device_type": self.device_type_var.get(),
            "hostname": self.hostname_var.get().strip(),
            "ip_address": self.ip_var.get().strip(),
        }


class TopologyCanvas(ttk.Frame):
    """Canvas widget to render and interact with the topology graph."""

    NODE_RADIUS = 25

    def __init__(
        self,
        master: tk.Misc,
        manager: TopologyManager,
        *,
        on_node_double_click: Optional[Callable[[str], None]] = None,
    ) -> None:
        super().__init__(master, padding=5)
        self.manager = manager
        self.on_node_double_click = on_node_double_click

        self.canvas = tk.Canvas(self, background="white")
        self.canvas.pack(fill="both", expand=True)

        self.node_widgets: Dict[str, Tuple[int, int]] = {}
        self.edge_widgets: Dict[Tuple[str, str], int] = {}
        self.selected_node: Optional[str] = None
        self.dragging_node: Optional[str] = None
        self.drag_offset: Tuple[float, float] = (0.0, 0.0)

        self.canvas.bind("<ButtonPress-1>", self._on_press)
        self.canvas.bind("<ButtonRelease-1>", self._on_release)
        self.canvas.bind("<B1-Motion>", self._on_drag)
        self.canvas.bind("<Double-Button-1>", self._on_double_click)
        self.canvas.bind("<Configure>", lambda event: self.render())

    # ------------------------------------------------------------------ #
    # Rendering

    def render(self) -> None:
        """Re-draw the entire topology."""
        self.canvas.delete("all")
        self.node_widgets.clear()
        self.edge_widgets.clear()

        devices = self.manager.get_devices()
        links = self.manager.get_links()

        for source, target, data in links:
            self._draw_link(source, target, data.get("link_type", "wired"))

        for node_id, attrs in devices.items():
            self._draw_node(node_id, attrs)

        if self.selected_node and self.selected_node in self.node_widgets:
            self._highlight_node(self.selected_node)

    def _draw_link(self, source: str, target: str, link_type: str) -> None:
        source_pos = self._get_canvas_position(source)
        target_pos = self._get_canvas_position(target)
        if not source_pos or not target_pos:
            return

        color = "#b1b5ba" if link_type == "wired" else "#38a169"
        line_id = self.canvas.create_line(
            *source_pos,
            *target_pos,
            width=2,
            fill=color,
            arrow="last",
            smooth=True,
        )
        self.edge_widgets[self._edge_key(source, target)] = line_id

    def _draw_node(self, node_id: str, attrs: Dict[str, object]) -> None:
        x, y = self._get_canvas_position(node_id)
        color = self._get_node_color(str(attrs.get("device_type", "Device")))
        oval_id = self.canvas.create_oval(
            x - self.NODE_RADIUS,
            y - self.NODE_RADIUS,
            x + self.NODE_RADIUS,
            y + self.NODE_RADIUS,
            fill=color,
            outline="black",
            width=2,
            tags=(f"node:{node_id}", "node"),
        )
        label = attrs.get("hostname", node_id)
        text_id = self.canvas.create_text(
            x,
            y,
            text=label,
            fill="white",
            font=("TkDefaultFont", 10, "bold"),
            tags=(f"node_text:{node_id}",),
        )
        self.node_widgets[node_id] = (oval_id, text_id)

    def _highlight_node(self, node_id: str) -> None:
        for nid, (oval_id, _) in self.node_widgets.items():
            outline = "#f6c343" if nid == node_id else "black"
            self.canvas.itemconfigure(oval_id, outline=outline, width=3 if nid == node_id else 2)

    # ------------------------------------------------------------------ #
    # Mouse interactions

    def _on_press(self, event: tk.Event) -> None:
        node_id = self._detect_node(event.x, event.y)
        if node_id:
            self.selected_node = node_id
            self._highlight_node(node_id)

            node_coords = self.canvas.coords(self.node_widgets[node_id][0])
            center_x = (node_coords[0] + node_coords[2]) / 2
            center_y = (node_coords[1] + node_coords[3]) / 2
            self.dragging_node = node_id
            self.drag_offset = (event.x - center_x, event.y - center_y)
        else:
            self.selected_node = None
            self.dragging_node = None
            self.render()

    def _on_drag(self, event: tk.Event) -> None:
        if not self.dragging_node:
            return
        new_x = event.x - self.drag_offset[0]
        new_y = event.y - self.drag_offset[1]
        self._move_node(self.dragging_node, (new_x, new_y))

    def _on_release(self, event: tk.Event) -> None:
        if not self.dragging_node:
            return
        node_id = self.dragging_node
        self.dragging_node = None

        new_x = event.x - self.drag_offset[0]
        new_y = event.y - self.drag_offset[1]
        self._move_node(node_id, (new_x, new_y))
        normalized = self._canvas_to_normalized(new_x, new_y)
        self.manager.set_device_position(node_id, normalized)

    def _on_double_click(self, event: tk.Event) -> None:
        node_id = self._detect_node(event.x, event.y)
        if node_id and self.on_node_double_click:
            self.on_node_double_click(node_id)

    # ------------------------------------------------------------------ #
    # Helpers

    def _move_node(self, node_id: str, canvas_pos: Tuple[float, float]) -> None:
        oval_id, text_id = self.node_widgets[node_id]
        x, y = canvas_pos
        self.canvas.coords(
            oval_id,
            x - self.NODE_RADIUS,
            y - self.NODE_RADIUS,
            x + self.NODE_RADIUS,
            y + self.NODE_RADIUS,
        )
        self.canvas.coords(text_id, x, y)
        self._update_connected_edges(node_id)

    def _update_connected_edges(self, node_id: str) -> None:
        for (src, dst), line_id in self.edge_widgets.items():
            if src == node_id or dst == node_id:
                source_pos = self._get_node_center(src)
                target_pos = self._get_node_center(dst)
                if source_pos and target_pos:
                    self.canvas.coords(line_id, *source_pos, *target_pos)

    def _get_node_center(self, node_id: str) -> Optional[Tuple[float, float]]:
        if node_id not in self.node_widgets:
            return None
        oval_id, _ = self.node_widgets[node_id]
        x1, y1, x2, y2 = self.canvas.coords(oval_id)
        return ((x1 + x2) / 2, (y1 + y2) / 2)

    def _detect_node(self, x: float, y: float) -> Optional[str]:
        items = self.canvas.find_overlapping(x, y, x, y)
        for item in items:
            tags = self.canvas.gettags(item)
            for tag in tags:
                if tag.startswith("node:"):
                    return tag.split(":", 1)[1]
        return None

    def _get_canvas_position(self, node_id: str) -> Optional[Tuple[float, float]]:
        devices = self.manager.get_devices()
        if node_id not in devices:
            return None
        pos = devices[node_id].get("position", (0.5, 0.5))
        return self._normalized_to_canvas(pos)

    def _normalized_to_canvas(self, position: Iterable[float]) -> Tuple[float, float]:
        width = max(self.canvas.winfo_width(), 1)
        height = max(self.canvas.winfo_height(), 1)
        padding = 60
        usable_w = max(width - 2 * padding, 1)
        usable_h = max(height - 2 * padding, 1)
        px = padding + float(position[0]) * usable_w
        py = padding + float(position[1]) * usable_h
        return (px, py)

    def _canvas_to_normalized(self, x: float, y: float) -> Tuple[float, float]:
        width = max(self.canvas.winfo_width(), 1)
        height = max(self.canvas.winfo_height(), 1)
        padding = 60
        usable_w = max(width - 2 * padding, 1)
        usable_h = max(height - 2 * padding, 1)
        norm_x = min(max((x - padding) / usable_w, 0.0), 1.0)
        norm_y = min(max((y - padding) / usable_h, 0.0), 1.0)
        return (norm_x, norm_y)

    @staticmethod
    def _edge_key(source: str, target: str) -> Tuple[str, str]:
        return tuple(sorted((source, target)))

    @staticmethod
    def _get_node_color(device_type: str) -> str:
        palette = {
            "router": "#2c7be5",
            "switch": "#6f42c1",
            "server": "#fd7e14",
            "pc": "#20c997",
        }
        return palette.get(device_type.lower(), "#6c757d")


class TopologyApp(ttk.Frame):
    """Composite widget representing the entire application."""

    def __init__(self, master: tk.Misc, manager: TopologyManager) -> None:
        super().__init__(master, padding=10)
        self.master = master
        self.manager = manager

        self.pack(fill="both", expand=True)

        self._create_widgets()
        self._populate_list()

    # ------------------------------------------------------------------ #
    # UI construction

    def _create_widgets(self) -> None:
        self.columnconfigure(0, weight=0)
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)
        self.rowconfigure(1, weight=0)

        control_frame = ttk.Frame(self, padding=(0, 0, 10, 0))
        control_frame.grid(row=0, column=0, sticky="ns")
        control_frame.columnconfigure(0, weight=1)

        ttk.Label(control_frame, text="Devices").grid(row=0, column=0, sticky="w")

        self.device_list = tk.Listbox(control_frame, selectmode="extended", height=15)
        self.device_list.grid(row=1, column=0, sticky="nsew", pady=5)
        control_frame.rowconfigure(1, weight=1)
        self.device_list.bind("<<ListboxSelect>>", lambda event: self._on_list_select())
        self.device_list.bind("<Double-Button-1>", lambda event: self._edit_selected_device())

        btn_frame = ttk.Frame(control_frame)
        btn_frame.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        for idx, (text, command) in enumerate(
            [
                ("Add Device", self._add_device),
                ("Edit Device", self._edit_selected_device),
                ("Remove Device", self._remove_selected_device),
                ("Connect Devices", self._connect_devices),
                ("Remove Link", self._remove_link),
                ("Auto Layout", self._auto_layout),
                ("Load Example", self._load_example),
                ("Import JSON", self._import_json),
                ("Export JSON", self._export_json),
            ]
        ):
            ttk.Button(btn_frame, text=text, command=command).grid(
                row=idx, column=0, sticky="ew", pady=2
            )

        self.canvas = TopologyCanvas(
            self,
            self.manager,
            on_node_double_click=lambda node_id: self._edit_device(node_id),
        )
        self.canvas.grid(row=0, column=1, sticky="nsew")

        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self, textvariable=self.status_var, relief="sunken", anchor="w")
        status_bar.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(10, 0))

    # ------------------------------------------------------------------ #
    # Event handlers

    def _on_list_select(self) -> None:
        selection = self._get_selected_nodes()
        node_id = selection[0] if selection else None
        self.canvas.selected_node = node_id
        self.canvas.render()

    def _add_device(self) -> None:
        dialog = DeviceDialog(self.master, "Add device")
        if not dialog.result_data:
            return
        data = dialog.result_data
        node_id = self.manager.add_device(
            data["device_type"], data["hostname"], data["ip_address"], position=(0.5, 0.5)
        )
        self.status_var.set(f"Added device {node_id}")
        self._populate_list()
        self.canvas.render()

    def _edit_device(self, node_id: str) -> None:
        devices = self.manager.get_devices()
        if node_id not in devices:
            return
        initial = {
            "device_type": devices[node_id].get("device_type", DEVICE_TYPES[0]),
            "hostname": devices[node_id].get("hostname", ""),
            "ip_address": devices[node_id].get("ip_address", ""),
        }
        dialog = DeviceDialog(self.master, f"Edit {node_id}", initial=initial)
        if not dialog.result_data:
            return
        data = dialog.result_data
        self.manager.update_device(
            node_id,
            device_type=data["device_type"],
            hostname=data["hostname"],
            ip_address=data["ip_address"],
        )
        self.status_var.set(f"Updated device {node_id}")
        self._populate_list(select=node_id)
        self.canvas.render()

    def _edit_selected_device(self) -> None:
        selection = self._get_selected_nodes()
        if not selection:
            messagebox.showinfo("Edit device", "Please select a device to edit.")
            return
        self._edit_device(selection[0])

    def _remove_selected_device(self) -> None:
        selection = self._get_selected_nodes()
        if not selection:
            messagebox.showinfo("Remove device", "Please select a device to remove.")
            return
        for node_id in selection:
            self.manager.remove_device(node_id)
        self.status_var.set(f"Removed {len(selection)} device(s)")
        self._populate_list()
        self.canvas.render()

    def _connect_devices(self) -> None:
        selection = self._get_selected_nodes()
        if len(selection) != 2:
            messagebox.showinfo(
                "Connect devices", "Select exactly two devices in the list to create a link."
            )
            return
        link_type = simpledialog.askstring(
            "Link type",
            "Enter link type (wired/wireless):",
            initialvalue="wired",
            parent=self.master,
        )
        if link_type is None:
            return
        link_type = link_type.strip().lower()
        if link_type not in LINK_TYPES:
            messagebox.showerror("Invalid link type", "Link type must be 'wired' or 'wireless'.")
            return
        try:
            self.manager.add_link(selection[0], selection[1], link_type=link_type)
        except (KeyError, ValueError) as exc:
            messagebox.showerror("Connect devices", str(exc))
            return
        self.status_var.set(f"Connected {selection[0]} to {selection[1]} ({link_type})")
        self.canvas.render()

    def _remove_link(self) -> None:
        selection = self._get_selected_nodes()
        if len(selection) != 2:
            messagebox.showinfo(
                "Remove link", "Select exactly two devices in the list to remove their link."
            )
            return
        try:
            self.manager.remove_link(selection[0], selection[1])
        except KeyError as exc:
            messagebox.showerror("Remove link", str(exc))
            return
        self.status_var.set(f"Removed link between {selection[0]} and {selection[1]}")
        self.canvas.render()

    def _auto_layout(self) -> None:
        layout = self.manager.compute_layout()
        if not layout:
            self.status_var.set("Nothing to layout.")
        else:
            self.status_var.set("Applied force-directed layout.")
        self.canvas.render()

    def _import_json(self) -> None:
        file_path = filedialog.askopenfilename(
            title="Import topology",
            filetypes=[("JSON files", "*.json")],
        )
        if not file_path:
            return
        try:
            TopologyIO.import_from_json(self.manager, file_path)
        except Exception as exc:  # pylint: disable=broad-except
            messagebox.showerror("Import failed", f"Could not import topology:\n{exc}")
            return
        self.status_var.set(f"Imported topology from {file_path}")
        self._populate_list()
        self.canvas.render()

    def _export_json(self) -> None:
        file_path = filedialog.asksaveasfilename(
            title="Export topology",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
        )
        if not file_path:
            return
        try:
            TopologyIO.export_to_json(self.manager, file_path)
        except Exception as exc:  # pylint: disable=broad-except
            messagebox.showerror("Export failed", f"Could not export topology:\n{exc}")
            return
        self.status_var.set(f"Exported topology to {file_path}")

    def _load_example(self) -> None:
        from pathlib import Path

        example_path = Path(__file__).resolve().parent.parent / "data" / "example_topology.json"
        try:
            TopologyIO.import_from_json(self.manager, str(example_path))
        except FileNotFoundError:
            messagebox.showerror("Example data", "Example topology file is missing.")
            return
        except Exception as exc:  # pylint: disable=broad-except
            messagebox.showerror("Example data", f"Could not load example topology:\n{exc}")
            return
        self.status_var.set("Loaded example topology.")
        self._populate_list()
        self.canvas.render()

    # ------------------------------------------------------------------ #
    # Helpers

    def _populate_list(self, *, select: Optional[str] = None) -> None:
        devices = self.manager.get_devices()
        sorted_items = sorted(
            devices.items(),
            key=lambda item: item[1].get("hostname", item[0]).lower(),
        )

        self.device_list.delete(0, tk.END)
        for node_id, data in sorted_items:
            hostname = data.get("hostname", node_id)
            device_type = data.get("device_type", "Device")
            self.device_list.insert(tk.END, f"{hostname} ({device_type}) [{node_id}]")

        if select:
            for index, (node_id, _) in enumerate(sorted_items):
                if node_id == select:
                    self.device_list.selection_set(index)
                    break

    def _get_selected_nodes(self) -> Tuple[str, ...]:
        selected_indices = self.device_list.curselection()
        devices = self.manager.get_devices()
        sorted_ids = [
            node_id
            for node_id, _ in sorted(
                devices.items(),
                key=lambda item: item[1].get("hostname", item[0]).lower(),
            )
        ]
        return tuple(sorted_ids[index] for index in selected_indices)


def run_app() -> None:
    root = tk.Tk()
    root.title("Network Topology Builder")
    root.geometry("1100x700")

    style = ttk.Style()
    if "clam" in style.theme_names():
        style.theme_use("clam")

    manager = TopologyManager()
    app = TopologyApp(root, manager)

    root.mainloop()


__all__ = ["TopologyApp", "TopologyCanvas", "run_app"]

