#!/usr/bin/env python3
"""Light desktop view of one session scored by a safeguard bundle (Tkinter + matplotlib).

  python3 TCN-gui/tcn_gui.py [--bundle DIR] [--input NPZ|DIR] [--diagnostic]
  python3 TCN-gui/tcn_gui.py --bundle DIR --input NPZ --png out.png    # no window

Two panels on one time axis: the anomaly score with threshold and alarms, and
the model's per-bin error over guest RAM (where in memory it is unusual). One
text line gives the selected training epoch and the dominant workload class.

Scores come from safeguard.runtime.Detector (analyza.py), the same as the live
detector. An anomaly is a deviation from benign training data, not a malware verdict.
"""
import argparse
from pathlib import Path
import sys

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import analyza  # noqa: E402

COLORS = {"ok": "#1f9d55", "alarm": "#d1343a", "unknown": "#d98a00", "error": "#d1343a"}


def _spans(t, flags, step):
    out, start = [], None
    for i, flag in enumerate(flags):
        if flag and start is None:
            start = t[i]
        if start is not None and (not flag or i == len(flags) - 1):
            out.append((start, (t[i] if flag else t[i - 1]) + step))
            start = None
    return out


def draw(fig, report):
    """Two panels: anomaly score, and per-bin model error over the same time axis."""
    from matplotlib.colors import LogNorm

    fig.clear()
    ax, ax2 = fig.subplots(2, 1, sharex=True, gridspec_kw={"height_ratios": [1, 1.4], "hspace": 0.12})
    fig.subplots_adjust(left=0.07, right=0.93, top=0.88, bottom=0.12)
    s, verdict, context = report["series"], report["verdict"], report["input"]["context"]
    t0 = s["t"][0] if s["t"] else 0.0
    minutes = np.array([(t - t0) / 60 for t in s["t"]])
    step = (minutes[1] - minutes[0]) if len(minutes) > 1 else 0.1
    end = minutes[-1] + step if len(minutes) else 1
    score = np.array([np.nan if v is None else v for v in s["score"]])
    summary = report["summary"]
    name = context.get("session_id") or Path(report["input"]["session_dir"]).name
    alarms = summary["model_alarm_events"]
    fig.suptitle(f"{verdict['label']}  ({alarms} alarm{'y' if 1 < alarms < 5 else '' if alarms == 1 else 'ov'})   {name}",
                 color=COLORS[verdict["level"]], fontsize=13, fontweight="bold", x=0.07, ha="left")

    for a, b in _spans(minutes, s["model_alarm"], step):
        ax.axvspan(a, b, color=COLORS["alarm"], alpha=0.15, lw=0)
    for e in context.get("events", []):
        if e.get("start") and e.get("stop") and e.get("executed"):
            ax.axvspan((e["start"] - t0) / 60, (e["stop"] - t0) / 60, color="#7b5cd6", alpha=0.12, lw=0)
    ax.plot(minutes, score, color="#2f6fde", lw=1.2)
    ax.axhline(report["threshold"], color=COLORS["alarm"], ls="--", lw=1)
    finite = score[np.isfinite(score)]
    if finite.size and finite.max() > 20 * max(np.median(finite), 1e-9):
        ax.set_yscale("log")
    ax.set_ylabel("skóre")
    ax.set_title(f"Skóre anomálie, prah {report['threshold']:.3g} (alarm: {report['k']} z {report['n']} okien nad prahom)",
                 fontsize=10, loc="left")
    ax.grid(alpha=0.25)

    bins = report["bins"]
    z = np.array([[np.nan if row is None or row[b] is None else row[b] for row in bins["errors"]]
                  for b in range(len(bins["ids"]))], dtype=float)
    positive = z[np.isfinite(z) & (z > 0)]
    if positive.size:
        image = ax2.imshow(z, aspect="auto", interpolation="nearest", cmap="inferno",
                           norm=LogNorm(vmin=np.percentile(positive, 1), vmax=positive.max()),
                           extent=(0, end, len(bins["ids"]), 0))
        fig.colorbar(image, cax=ax2.inset_axes([1.01, 0, 0.015, 1])).set_label("chyba (log)", fontsize=8)
    ticks = np.linspace(0, len(bins["ids"]) - 1, min(8, len(bins["ids"]))).astype(int)
    ax2.set_yticks(ticks + 0.5, [f"{bins['gpa_mib'][i]:.0f}" for i in ticks], fontsize=8)
    ax2.set_ylabel("adresa RAM hosťa [MiB]")
    ax2.set_xlabel("minúty")
    ax2.set_title("Chyba modelu po oblastiach pamäte (16 MiB biny)", fontsize=10, loc="left")
    ax.set_xlim(0, end)

    model = report["model"]
    classes = list(s["activity"])
    stack = np.array([[np.nan if v is None else v for v in s["activity"][c]] for c in classes], dtype=float)
    valid = np.isfinite(stack).all(axis=0)
    line = (f"Model {model['name']}: vybraná epocha {model.get('selected_predictor_epoch')} z {model.get('epochs')}, "
            f"strata dev {model['history'][-1]['dev_prediction_loss']:.3g}" if model.get("history") else f"Model {model['name']}")
    if valid.any():
        mean = stack[:, valid].mean(axis=1)
        line += f".  Klasifikácia záťaže: {classes[int(np.argmax(mean))]} ({mean.max():.0%})"
        if context.get("scenario"):
            line += f", zaznamenaný scenár {context['scenario']}"
    fig.text(0.07, 0.025, line + ".", fontsize=9, color="#444")
    return fig


SETTINGS = Path.home() / ".config" / "hyptcn3-tcn-gui.json"
MARK = {"ok": "✓ bez alarmu", "alarm": "✗ ", "unknown": "? pokrytie", "error": "chyba"}


def find_sessions(folder):
    """Session inputs one level deep (archive .npz or raw/ with .vmicd); never walks deeper."""
    folder = Path(folder)
    found = []
    for item in sorted(folder.iterdir()):
        if item.is_file() and item.suffix == ".npz":
            found.append(item)
        elif item.is_dir() and (any(item.glob("*.npz")) or any(item.glob("*.vmicd"))
                                or (item / "raw").is_dir()):
            found.append(item)
    return found


class App:
    """Mini application: load a model, pick a folder of sessions, click through or check all."""

    def __init__(self, bundle=None, source=None, diagnostic=False):
        import json
        import queue
        import tkinter as tk
        from tkinter import ttk
        from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
        from matplotlib.figure import Figure

        self.json, self.tk, self.queue = json, tk, queue.Queue()
        self.settings = {}
        try:
            self.settings = json.loads(SETTINGS.read_text())
        except (OSError, ValueError):
            pass
        self.root = root = tk.Tk()
        root.title("TCN detektor")
        root.geometry("1450x860")
        self.bundle, self.bundle_path, self.report, self.reports, self.busy = None, None, None, {}, False
        self.diagnostic = tk.BooleanVar(value=diagnostic)
        self.status = tk.StringVar(value="Načítaj model a potom session alebo priečinok so session.")

        menu = tk.Menu(root)
        file_menu = tk.Menu(menu, tearoff=False)
        file_menu.add_command(label="Načítať model…", accelerator="Ctrl+M", command=self.choose_model)
        file_menu.add_command(label="Otvoriť session (.npz)…", accelerator="Ctrl+O", command=self.choose_file)
        file_menu.add_command(label="Otvoriť priečinok so session…", accelerator="Ctrl+D", command=self.choose_folder)
        file_menu.add_separator()
        file_menu.add_command(label="Uložiť obrázok…", accelerator="Ctrl+S", command=self.save_png)
        file_menu.add_command(label="Uložiť prehľad (CSV)…", command=self.save_csv)
        file_menu.add_separator()
        file_menu.add_command(label="Koniec", accelerator="Ctrl+Q", command=root.destroy)
        menu.add_cascade(label="Súbor", menu=file_menu)
        root.config(menu=menu)
        for key, action in (("m", self.choose_model), ("o", self.choose_file), ("d", self.choose_folder),
                            ("s", self.save_png), ("q", root.destroy)):
            root.bind(f"<Control-{key}>", lambda _e, f=action: f())

        ttk.Label(root, textvariable=self.status, relief="sunken", padding=(6, 2)).pack(side="bottom", fill="x")
        side = ttk.Frame(root, padding=8, width=360)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        model_box = ttk.LabelFrame(side, text="Model", padding=6)
        model_box.pack(fill="x")
        ttk.Button(model_box, text="Načítať model…", command=self.choose_model).pack(fill="x")
        ttk.Checkbutton(model_box, text="povoliť diagnostický (syntetický) balík",
                        variable=self.diagnostic).pack(anchor="w", pady=(4, 0))
        self.model_info = ttk.Label(model_box, text="žiadny model", wraplength=330, justify="left",
                                    foreground="#5d6673")
        self.model_info.pack(fill="x", pady=(4, 0))

        list_box = ttk.LabelFrame(side, text="Session", padding=6)
        list_box.pack(fill="both", expand=True, pady=(8, 0))
        row = ttk.Frame(list_box)
        row.pack(fill="x")
        ttk.Button(row, text="Session…", command=self.choose_file).pack(side="left", expand=True, fill="x")
        ttk.Button(row, text="Priečinok…", command=self.choose_folder).pack(side="left", expand=True, fill="x")
        self.tree = ttk.Treeview(list_box, columns=("verdict", "max"), show="tree headings", selectmode="browse")
        self.tree.heading("#0", text="session")
        self.tree.heading("verdict", text="výsledok")
        self.tree.heading("max", text="max×")
        self.tree.column("#0", width=170)
        self.tree.column("verdict", width=95)
        self.tree.column("max", width=60, anchor="e")
        self.tree.tag_configure("alarm", foreground=COLORS["alarm"])
        self.tree.tag_configure("ok", foreground=COLORS["ok"])
        self.tree.tag_configure("unknown", foreground=COLORS["unknown"])
        self.tree.tag_configure("error", foreground=COLORS["error"])
        self.tree.pack(fill="both", expand=True, pady=6)
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self.show_selected())
        self.tree.bind("<Return>", lambda _e: self.analyze_selected())
        self.tree.bind("<Double-1>", lambda _e: self.analyze_selected())
        ttk.Button(list_box, text="Analyzovať vybranú  (Enter)", command=self.analyze_selected).pack(fill="x")
        ttk.Button(list_box, text="Skontrolovať všetky", command=self.analyze_all).pack(fill="x", pady=(4, 0))
        self.progress = ttk.Progressbar(list_box, mode="determinate")
        self.progress.pack(fill="x", pady=(6, 0))

        right = ttk.Frame(root)
        right.pack(side="left", fill="both", expand=True)
        self.figure = Figure(figsize=(11, 7), dpi=100)
        self.figure.text(0.5, 0.5, "Žiadna analýza", ha="center", va="center", color="#9aa4b2", fontsize=14)
        self.canvas = FigureCanvasTkAgg(self.figure, master=right)
        NavigationToolbar2Tk(self.canvas, right).pack(side="bottom", fill="x")
        self.canvas.get_tk_widget().pack(side="top", fill="both", expand=True)

        bundle = bundle or self.settings.get("bundle")
        if bundle and Path(bundle).is_dir():
            self.load_model(bundle, quiet=not diagnostic)
        if source:
            self.add_inputs([Path(source)], select=True)
        elif self.settings.get("folder") and Path(self.settings["folder"]).is_dir():
            self.add_inputs(find_sessions(self.settings["folder"]))
        root.after(100, self.poll)

    # -- settings and choices -------------------------------------------------
    def remember(self, **values):
        self.settings.update({k: str(v) for k, v in values.items()})
        try:
            SETTINGS.parent.mkdir(parents=True, exist_ok=True)
            SETTINGS.write_text(self.json.dumps(self.settings, indent=1))
        except OSError:
            pass

    def start_dir(self):
        return self.settings.get("folder") or str(analyza.ROOT / "data")

    def choose_model(self):
        from tkinter import filedialog
        path = filedialog.askdirectory(title="Adresár modelu (obsahuje manifest.json)",
                                       initialdir=self.settings.get("bundle") or analyza.ROOT / "data")
        if path:
            self.load_model(path)

    def choose_file(self):
        from tkinter import filedialog
        path = filedialog.askopenfilename(title="Archív príznakov session", initialdir=self.start_dir(),
                                          filetypes=[("archív príznakov", "*.npz"), ("všetko", "*")])
        if path:
            self.add_inputs([Path(path)], select=True)

    def choose_folder(self):
        from tkinter import filedialog, messagebox
        path = filedialog.askdirectory(title="Priečinok so session (napr. data/collections)",
                                       initialdir=self.start_dir())
        if not path:
            return
        found = find_sessions(path)
        if not found:
            messagebox.showinfo("TCN detektor", "V priečinku nie sú session (.npz alebo raw/ so snímkami).")
            return
        self.remember(folder=path)
        self.tree.delete(*self.tree.get_children())
        self.add_inputs(found)
        self.status.set(f"{len(found)} session v {path}. Vyber jednu alebo „Skontrolovať všetky“.")

    def load_model(self, path, quiet=False):
        from tkinter import messagebox
        from safeguard.bundle import load_bundle
        try:
            self.bundle = load_bundle(path, allow_diagnostic=self.diagnostic.get())
        except (ValueError, OSError, KeyError, RuntimeError) as exc:
            if not quiet:
                messagebox.showerror("TCN detektor", f"Model sa nenačítal:\n{exc}")
            return
        self.bundle_path = Path(path)
        self.reports.clear()
        for item in self.tree.get_children():
            self.tree.item(item, values=("", ""), tags=())
        info = analyza.model_summary(self.bundle)
        self.model_info.config(text=(
            f"{self.bundle_path.name}{' (diagnostický)' if info['diagnostic'] else ''}\n"
            f"epocha {info['selected_predictor_epoch']}/{info['epochs']}, okno {info['feature_contract']['window_rows']} snímok, "
            f"{info['feature_contract']['bins']} binov\n"
            f"prah {info['calibration'].get('threshold', 0):.4g}, alarm {info['calibration'].get('k')} z "
            f"{info['calibration'].get('n')}\ntriedy: {', '.join(info['classes'])}"))
        self.remember(bundle=path)
        self.status.set(f"Model {self.bundle_path.name} načítaný.")

    def add_inputs(self, paths, select=False):
        for path in paths:
            key = str(path.resolve())
            if not self.tree.exists(key):
                self.tree.insert("", "end", iid=key, text=path.stem if path.is_file() else path.name,
                                 values=("", ""))
        if select and paths:
            key = str(paths[-1].resolve())
            self.tree.selection_set(key)
            self.tree.see(key)
            self.analyze_selected()

    # -- analysis in a worker thread ------------------------------------------
    def selected(self):
        chosen = self.tree.selection()
        return chosen[0] if chosen else None

    def show_selected(self):
        key = self.selected()
        if key in self.reports:
            self.show(self.reports[key])

    def analyze_selected(self):
        key = self.selected()
        if key:
            self.start([key])

    def analyze_all(self):
        keys = [k for k in self.tree.get_children() if k not in self.reports]
        if keys:
            self.start(keys)
        else:
            self.status.set("Všetky session sú už skontrolované.")

    def start(self, keys):
        import threading
        from tkinter import messagebox
        if self.busy:
            return
        if self.bundle is None:
            messagebox.showinfo("TCN detektor", "Najprv načítaj model.")
            return
        if analyza.busy_collecting():
            messagebox.showwarning("TCN detektor", "Na tomto PC beží zber. Prehratie by zaťažilo CPU a disk "
                                   "a narušilo meranie; spusti analýzu po zbere alebo na inom PC.")
            return
        self.busy = True
        self.progress.config(maximum=len(keys), value=0)
        self.root.config(cursor="watch")
        threading.Thread(target=self.work, args=(keys,), daemon=True).start()

    def work(self, keys):
        for i, key in enumerate(keys, 1):
            self.queue.put(("status", f"Analyzujem {i}/{len(keys)}: {Path(key).name}…"))
            try:
                report = analyza.analyze(self.bundle_path, key, bundle=self.bundle)
                self.queue.put(("report", key, report, len(keys) == 1))
            except (ValueError, OSError, RuntimeError, KeyError) as exc:
                self.queue.put(("error", key, f"{type(exc).__name__}: {exc}"))
            self.queue.put(("progress", i))
        self.queue.put(("done", len(keys)))

    def poll(self):
        while not self.queue.empty():
            message = self.queue.get()
            kind = message[0]
            if kind == "status":
                self.status.set(message[1])
            elif kind == "progress":
                self.progress.config(value=message[1])
            elif kind == "report":
                _, key, report, show = message
                self.reports[key] = report
                level, s = report["verdict"]["level"], report["summary"]
                label = MARK[level] + (f"{s['model_alarm_events']} alarm" if level == "alarm" else "")
                ratio = f"{s['score_max'] / report['threshold']:.1f}×" if s["score_max"] is not None else "–"
                self.tree.item(key, values=(label, ratio), tags=(level,))
                if show or key == self.selected():
                    self.show(report)
            elif kind == "error":
                _, key, text = message
                self.tree.item(key, values=("chyba", ""), tags=("error",))
                self.status.set(text)
            elif kind == "done":
                self.busy = False
                self.root.config(cursor="")
                alarms = sum(r["verdict"]["level"] == "alarm" for r in self.reports.values())
                self.status.set(f"Hotovo. Skontrolovaných {len(self.reports)}, s alarmom {alarms}.")
        self.root.after(100, self.poll)

    def show(self, report):
        self.report = report
        draw(self.figure, report)
        self.canvas.draw_idle()

    # -- export -----------------------------------------------------------------
    def save_png(self):
        from tkinter import filedialog, messagebox
        if self.report is None:
            messagebox.showinfo("TCN detektor", "Najprv analyzuj session.")
            return
        name = Path(self.report["input"]["session_dir"]).name + ".png"
        path = filedialog.asksaveasfilename(defaultextension=".png", initialfile=name,
                                            filetypes=[("PNG", "*.png"), ("PDF", "*.pdf"), ("SVG", "*.svg")])
        if path:
            self.figure.savefig(path, dpi=150)
            self.status.set(f"Uložené: {path}")

    def save_csv(self):
        import csv
        from tkinter import filedialog, messagebox
        if not self.reports:
            messagebox.showinfo("TCN detektor", "Zatiaľ nie je nič skontrolované.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", initialfile="prehlad.csv",
                                            filetypes=[("CSV", "*.csv")])
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as stream:
            out = csv.writer(stream)
            out.writerow(["session", "verdikt", "alarmy_modelu", "nalezy_integrity", "okien", "nad_prahom",
                          "max_skore", "prah", "model", "vstup"])
            for key, r in self.reports.items():
                s = r["summary"]
                out.writerow([Path(r["input"]["session_dir"]).name, r["verdict"]["label"], s["model_alarm_events"],
                              s["integrity_rows"], s["scored"], s["above_threshold"], s["score_max"],
                              r["threshold"], r["model"]["name"], key])
        self.status.set(f"Prehľad uložený: {path}")

    def run(self):
        self.root.mainloop()


def window(bundle=None, source=None, diagnostic=False):
    App(bundle, source, diagnostic).run()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--bundle", help="adresár balíka safeguard (manifest.json)")
    parser.add_argument("--input", help="archív .npz, adresár session alebo adresár snímok .vmicd")
    parser.add_argument("--diagnostic", action="store_true", help="povoliť diagnostický (syntetický) balík")
    parser.add_argument("--png", type=Path, help="bez okna: uložiť obrázok sem")
    args = parser.parse_args(argv)
    if args.png:
        if not (args.bundle and args.input):
            parser.error("--png potrebuje --bundle aj --input")
        import matplotlib
        matplotlib.use("Agg")
        from matplotlib.figure import Figure
        report = analyza.analyze(args.bundle, args.input, allow_diagnostic=args.diagnostic)
        draw(Figure(figsize=(13, 7), dpi=110), report).savefig(args.png)
        print(f"{report['verdict']['label']}: {args.png}")
        return 0
    window(args.bundle, args.input, args.diagnostic)
    return 0


if __name__ == "__main__":
    sys.exit(main())
