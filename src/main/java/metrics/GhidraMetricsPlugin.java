package metrics;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;


//@formatter:off
@PluginInfo(
        status = PluginStatus.UNSTABLE,
        packageName = GhidraMetricsPlugin.PACKAGE_NAME,
        category = PluginCategoryNames.EXAMPLES,
        shortDescription = "Collection of Metrics",
        description = "This plugin provides a collection of metrics to be computed on a native binary"
)
//@formatter:on
public class GhidraMetricsPlugin extends ProgramPlugin {

    public static final String PACKAGE_NAME = "metrics";
    GhidraMetricsProvider provider;

    public GhidraMetricsPlugin(PluginTool plugintool) {
        super(plugintool);
        String pluginName = getName();
        provider = new GhidraMetricsProvider(this, pluginName);
    }

}
