"""Tests for the shared config extension base (ConfigChange, ConfigPlan, ConfigFormatter)."""

from octorules_bunny._config_base import ConfigChange, ConfigFormatter, ConfigPlan


class TestConfigChange:
    def test_has_changes_true(self):
        c = ConfigChange(section="bot", field="mode", current="off", desired="log")
        assert c.has_changes is True

    def test_has_changes_false(self):
        c = ConfigChange(section="bot", field="mode", current="off", desired="off")
        assert c.has_changes is False

    def test_has_changes_none_vs_value(self):
        c = ConfigChange(section="bot", field="mode", current=None, desired="log")
        assert c.has_changes is True


class TestConfigPlan:
    def test_empty_plan(self):
        p = ConfigPlan()
        assert p.has_changes is False
        assert p.total_changes == 0

    def test_plan_with_changes(self):
        p = ConfigPlan(
            changes=[
                ConfigChange(section="a", field="x", current=1, desired=2),
                ConfigChange(section="a", field="y", current=3, desired=3),
                ConfigChange(section="b", field="z", current=4, desired=5),
            ]
        )
        assert p.has_changes is True
        assert p.total_changes == 2

    def test_plan_no_actual_changes(self):
        p = ConfigPlan(changes=[ConfigChange(section="a", field="x", current=1, desired=1)])
        assert p.has_changes is False
        assert p.total_changes == 0


class TestConfigFormatter:
    def _make_plan(self, label_prefix="test"):
        return ConfigPlan(
            changes=[
                ConfigChange(section="sec", field="f1", current="old", desired="new"),
                ConfigChange(section="sec", field="f2", current=1, desired=1),  # no change
            ]
        )

    def test_format_text(self):
        fmt = ConfigFormatter("test_config")
        lines = fmt.format_text([self._make_plan()], use_color=False)
        assert len(lines) == 1
        assert "sec.f1" in lines[0]
        assert "'old'" in lines[0]
        assert "'new'" in lines[0]

    def test_format_text_skips_no_change(self):
        fmt = ConfigFormatter("test_config")
        lines = fmt.format_text([self._make_plan()], use_color=False)
        assert not any("f2" in line for line in lines)

    def test_format_json(self):
        fmt = ConfigFormatter("test_config")
        result = fmt.format_json([self._make_plan()])
        assert len(result) == 1
        assert len(result[0]["changes"]) == 1
        assert result[0]["changes"][0]["field"] == "f1"

    def test_format_markdown(self):
        fmt = ConfigFormatter("test_config")
        lines = fmt.format_markdown([self._make_plan()], [])
        assert len(lines) == 1
        assert "sec.f1" in lines[0]
        assert "|" in lines[0]

    def test_format_html(self):
        fmt = ConfigFormatter("test_config")
        lines: list[str] = []
        counts = fmt.format_html([self._make_plan()], lines)
        assert counts == (0, 0, 1, 0)  # adds, removes, modifies, errors
        assert any("Modify" in line for line in lines)

    def test_format_report_with_drift(self):
        fmt = ConfigFormatter("test_config")
        phases_data: list[dict] = []
        result = fmt.format_report([self._make_plan()], False, phases_data)
        assert result is True  # zone_has_drift
        assert len(phases_data) == 1
        assert phases_data[0]["provider_id"] == "test_config"
        assert phases_data[0]["modifies"] == 1

    def test_format_report_no_drift(self):
        fmt = ConfigFormatter("test_config")
        p = ConfigPlan(changes=[ConfigChange(section="s", field="f", current=1, desired=1)])
        phases_data: list[dict] = []
        result = fmt.format_report([p], False, phases_data)
        assert result is False
        assert len(phases_data) == 0

    def test_format_text_empty_plans(self):
        fmt = ConfigFormatter("x")
        assert fmt.format_text([], use_color=False) == []

    def test_format_json_empty_plans(self):
        fmt = ConfigFormatter("x")
        assert fmt.format_json([]) == []
