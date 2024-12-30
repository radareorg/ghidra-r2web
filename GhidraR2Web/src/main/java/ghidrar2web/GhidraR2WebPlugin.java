/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidrar2web;

import java.awt.BorderLayout;
import java.io.IOException;

import javax.swing.*;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import docking.tool.ToolConstants;
import docking.widgets.OkDialog;
import ghidra.app.CorePluginPackage;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import resources.Icons;

/**
 * Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = CorePluginPackage.NAME, // https://github.com/NationalSecurityAgency/ghidra/discussions/5175
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "Plugin short description goes here.",
	description = "Plugin long description goes here."
)
//@formatter:on
public class GhidraR2WebPlugin extends ProgramPlugin {

	MyProvider provider;
	

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public GhidraR2WebPlugin(PluginTool tool) {
		super(tool);

		// Customize provider (or remove if a provider is not desired)
		String pluginName = getName();
		provider = new MyProvider(this, pluginName);

		// Customize help (or remove if help is not desired)
		String topicName = this.getClass().getPackage().getName();
		String anchorName = "HelpAnchor";
		provider.setHelpLocation(new HelpLocation(topicName, anchorName));
	}

	@Override
	public void init() {
		super.init();

		// Acquire services if necessary
	}

	// If provider is desired, it is recommended to move it to its own file
	private static class MyProvider extends ComponentProvider {

		private JPanel panel;
		private DockingAction startAction;
		static GhidraR2WebServer webServer;

		public MyProvider(Plugin plugin, String owner) {
			super(plugin.getTool(), owner, owner);
			createActions();
		}

		// Customize actions
		private void createActions() {
			startAction = new DockingAction("R2Web Start Action", getName()) {
				@Override
				public void actionPerformed(ActionContext context) {
					try {
						webServer=GhidraR2WebServer.getInstance(9191);
					}catch(IOException ioe) {
						OkDialog.showError("R2Web Error", ioe.getMessage());
					}
				}
			};
			startAction.setMenuBarData(new MenuData(
		            new String[] {                      // Menu Path
		                ToolConstants.MENU_TOOLS,
		                "R2Web",
		                "Start R2Web server..."
		            },
		            null,                               // Icon
		            "r2web",                      // Menu Group
		            MenuData.NO_MNEMONIC,               // Mnemonic
		            "1"                                 // Menu Subgroup
		        ));
			//action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
			startAction.setEnabled(true);
			startAction.markHelpUnnecessary();
			dockingTool.addAction(startAction);
		}

		@Override
		public JComponent getComponent() {
			return panel;
		}
	}
}
