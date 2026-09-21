"""
fix_plugin_actions.py — патч tui/app.py.

Делает так, чтобы любые плагины, которые пользователь добавит в папку
plugins/, автоматически появлялись:
    1. Кнопкой в левой панели (секция "🧩 Плагины").
    2. Своими командами в выпадающем списке "Быстрое действие" внизу.

Достаточно нажать кнопку "🔄 Reload plugins" — и новые плагины подхватятся
без перезапуска TUI.
"""
import re
import sys
from pathlib import Path

candidates = [
    Path("tui/app.py"),
    Path(__file__).parent / "tui" / "app.py",
    Path.cwd() / "tui" / "app.py",
]
APP_PATH = next((c for c in candidates if c.exists()), None)

if not APP_PATH:
    print("[!] Не найден tui/app.py. Запусти из корня проекта.")
    sys.exit(1)

src = APP_PATH.read_text(encoding="utf-8")
backup = APP_PATH.with_suffix(".py.bak")
backup.write_text(src, encoding="utf-8")
patches = 0


# ============================================================================
# ПАТЧ 1: глобальная пересборка QUICK_ACTIONS
# ============================================================================
old1 = "QUICK_ACTIONS = _build_quick_actions()\n"
new1 = '''QUICK_ACTIONS: dict = _build_quick_actions()


def _rebuild_quick_actions() -> dict:
    """Пересобрать QUICK_ACTIONS (включая плагины) на лету.
    Вызывается при нажатии кнопки "Reload plugins"."""
    global QUICK_ACTIONS
    QUICK_ACTIONS = _build_quick_actions()
    return QUICK_ACTIONS
'''

if old1 in src and "_rebuild_quick_actions" not in src:
    src = src.replace(old1, new1, 1)
    patches += 1
    print("[+] Патч 1: пересборка QUICK_ACTIONS")
elif "_rebuild_quick_actions" in src:
    print("[=] Патч 1 уже применён")
else:
    print("[!] Патч 1: не найден якорь 'QUICK_ACTIONS = _build_quick_actions()'")


# ============================================================================
# ПАТЧ 2: секция плагинов в compose() → динамический контейнер
# ============================================================================
old2 = '''                        if group_name == "🧩 Плагины":
                            plugin_entries = _get_plugin_group_entries()
                            if plugin_entries:
                                for key, title in plugin_entries:
                                    yield Button(title, id=f"module-{key}")
                            else:
                                yield Label("[dim]  плагинов нет[/dim]")
                        else:
                            for key, title in modules:
                                yield Button(title, id=f"module-{key}")'''

new2 = '''                        if group_name == "🧩 Плагины":
                            with Vertical(id="plugin_buttons"):
                                yield Label("[dim]  загрузка…[/dim]")
                        else:
                            for key, title in modules:
                                yield Button(title, id=f"module-{key}")'''

if old2 in src:
    src = src.replace(old2, new2, 1)
    patches += 1
    print("[+] Патч 2: динамический контейнер для плагинов")
elif 'id="plugin_buttons"' in src:
    print("[=] Патч 2 уже применён")
else:
    print("[!] Патч 2: не найден якорь (секция плагинов в compose)")


# ============================================================================
# ПАТЧ 3: в on_mount() заполнить контейнер плагинов
# ============================================================================
old3 = '''        self._refresh_status()
        self.set_timer(0.3, lambda: self.refresh(layout=True))

    def _refresh_status(self) -> None:'''

new3 = '''        self._refresh_status()
        self.set_timer(0.3, lambda: self.refresh(layout=True))
        # Заполняем левую панель плагинами
        self.set_timer(0.1, self._populate_plugin_buttons)

    def _populate_plugin_buttons(self) -> None:
        """Пересобрать секцию плагинов в левой панели."""
        try:
            container = self.query_one("#plugin_buttons")
        except Exception:  # noqa: BLE001
            return

        async def _rebuild() -> None:
            try:
                await container.remove_children()
            except Exception:  # noqa: BLE001
                pass
            entries = _get_plugin_group_entries()
            if not entries:
                try:
                    await container.mount(
                        Label("[dim]  плагинов нет[/dim]")
                    )
                except Exception:  # noqa: BLE001
                    pass
                return
            for key, title in entries:
                try:
                    await container.mount(
                        Button(title, id=f"module-{key}")
                    )
                except Exception as exc:  # noqa: BLE001
                    log.debug("mount plugin button: %s", exc)

        try:
            self.run_worker(_rebuild(), exclusive=False)
        except Exception:  # noqa: BLE001
            pass

    def _refresh_status(self) -> None:'''

if old3 in src:
    src = src.replace(old3, new3, 1)
    patches += 1
    print("[+] Патч 3: метод _populate_plugin_buttons")
elif "_populate_plugin_buttons" in src:
    print("[=] Патч 3 уже применён")
else:
    print("[!] Патч 3: не найден якорь (on_mount / _refresh_status)")


# ============================================================================
# ПАТЧ 4: reload_plugins() — полный reload (реестр + QuickActions + UI + Select)
# ============================================================================
old4 = '''    def reload_plugins(self) -> None:
        self._clear()
        self._write("[cyan]🔄 Перечитываю плагины…[/cyan]")
        try:
            reg = plugin_loader.reload_plugins()
            self._write(f"[green]✓ Загружено: {len(reg)}[/green]")
            for name, data in reg.items():
                self._write(f"  [cyan]{name}[/cyan] "
                            f"[dim]v{data['version']} — "
                            f"{len(data['actions'])} действий[/dim]")
        except Exception as exc:  # noqa: BLE001
            self._write(f"[red]Ошибка: {exc}[/red]")'''

new4 = '''    def reload_plugins(self) -> None:
        """Полный reload: реестр плагинов + QUICK_ACTIONS + UI + Select."""
        self._clear()
        self._write("[cyan]🔄 Перечитываю плагины…[/cyan]")

        # 1. Перечитываем реестр ядра
        try:
            reg = plugin_loader.reload_plugins()
        except Exception as exc:  # noqa: BLE001
            self._write(f"[red]Ошибка reload: {exc}[/red]")
            return

        self._write(f"[green]✓ Загружено плагинов: {len(reg)}[/green]")
        for name, data in reg.items():
            self._write(f"  [cyan]{name}[/cyan] "
                        f"[dim]v{data['version']} — "
                        f"{len(data['actions'])} действий[/dim]")

        # 2. Пересобираем QUICK_ACTIONS (включая действия плагинов)
        try:
            qa = _rebuild_quick_actions()
            self._write(f"[green]✓ Собрано действий: {len(qa)}[/green]")
        except Exception as exc:  # noqa: BLE001
            self._write(f"[yellow]QuickActions: {exc}[/yellow]")

        # 3. Обновляем левую панель (кнопки плагинов)
        self._populate_plugin_buttons()

        # 4. Если сейчас выбран плагин — обновляем Select
        if self.current_module:
            self._refresh_action_select(self.current_module)

        # 5. Обновляем статус-бар
        self._refresh_status()

    def action_reload_plugins(self) -> None:
        self.reload_plugins()'''

if old4 in src:
    src = src.replace(old4, new4, 1)
    patches += 1
    print("[+] Патч 4: reload_plugins (полный reload)")
elif "def action_reload_plugins" in src:
    print("[=] Патч 4 уже применён")
else:
    print("[!] Патч 4: не найден якорь (старый reload_plugins)")


# ============================================================================
# ПАТЧ 5: _refresh_action_select — поддержка плагинов + обновление после reload
# ============================================================================
old5 = '''    def _refresh_action_select(self, module_key: str | None = None) -> None:
        try:
            sel = self.query_one("#action_select", Select)
        except Exception:  # noqa: BLE001
            return

        if not module_key:
            options = [("— сначала выбери модуль слева —", "__empty__")]
        else:
            prefix = PREFIX_MAP.get(module_key, f"{module_key}.")
            filtered = [
                (f"{k}  —  {v[2]}", k)
                for k, v in QUICK_ACTIONS.items()
                if k.startswith(prefix)
            ]
            if not filtered:
                options = [(f"⚠ Нет быстрых действий для '{module_key}'",
                            "__empty__")]
            else:
                options = filtered

        try:
            sel.set_options(options)
            try:
                sel.value = "__empty__"
            except Exception:
                pass
        except Exception as exc:  # noqa: BLE001
            log.debug("set_options: %s", exc)'''

new5 = '''    def _refresh_action_select(self, module_key: str | None = None) -> None:
        """Пересобрать Select с быстрыми действиями для модуля/плагина."""
        try:
            sel = self.query_one("#action_select", Select)
        except Exception:  # noqa: BLE001
            return

        if not module_key:
            options = [("— сначала выбери модуль слева —", "__empty__")]
        elif module_key.startswith("plugin-"):
            # Плагины: QUICK_ACTIONS-ключи такие — plugin.{pname}.{action}
            pname = module_key[len("plugin-"):]
            prefix = f"plugin.{pname}."
            filtered = [
                (f"{k}  —  {v[2]}", k)
                for k, v in QUICK_ACTIONS.items()
                if k.startswith(prefix)
            ]
            if not filtered:
                options = [(f"⚠ У плагина '{pname}' нет действий",
                            "__empty__")]
            else:
                options = filtered
        else:
            prefix = PREFIX_MAP.get(module_key, f"{module_key}.")
            filtered = [
                (f"{k}  —  {v[2]}", k)
                for k, v in QUICK_ACTIONS.items()
                if k.startswith(prefix)
            ]
            if not filtered:
                options = [(f"⚠ Нет быстрых действий для '{module_key}'",
                            "__empty__")]
            else:
                options = filtered

        # Обновляем Select через асинхронный Worker (в новых Textual нельзя
        # звать set_options синхронно при некоторых состояниях)
        async def _apply() -> None:
            try:
                sel.set_options(options)
                try:
                    sel.value = "__empty__"
                except Exception:
                    pass
            except Exception as exc:  # noqa: BLE001
                log.debug("set_options: %s", exc)

        try:
            self.run_worker(_apply(), exclusive=False)
        except Exception:
            # Fallback для старого API
            try:
                sel.set_options(options)
                try:
                    sel.value = "__empty__"
                except Exception:
                    pass
            except Exception as exc:  # noqa: BLE001
                log.debug("set_options sync fallback: %s", exc)'''

if old5 in src:
    src = src.replace(old5, new5, 1)
    patches += 1
    print("[+] Патч 5: _refresh_action_select (плагины + async)")
elif 'pname = module_key[len("plugin-"):]' in src:
    print("[=] Патч 5 уже применён")
else:
    print("[!] Патч 5: не найден якорь (_refresh_action_select)")


# ============================================================================
# Сохранение
# ============================================================================
APP_PATH.write_text(src, encoding="utf-8")

print()
print(f"[OK] Применено патчей: {patches}")
print(f"     Файл:  {APP_PATH}")
print(f"     Бэкап: {backup}")
print()
print("Запусти: start_tui.bat")
print("Затем:")
print("  1. Кликни на любой плагин в левой панели (hello, ip_info) —")
print("     его команды появятся в выпадающем списке внизу.")
print("  2. Добавь свой .py в plugins/ → нажми «🔄 Reload plugins» →")
print("     кнопка плагина и его команды появятся автоматически.")