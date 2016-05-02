if __name__ == "__main__":
    raise Exception("This script is a plugin for xsconsole and cannot run independently")
    
from XSConsoleStandard import *

class XSFeatureDisplayNICs:
    @classmethod
    def StatusUpdateHandler(cls, inPane):
	data = Ubuntu1204Data.Inst()
        
        inPane.AddTitleField(Lang("Network Interfaces"))
        
        for pif in data.host.PIFs([]):
            inPane.AddWrappedBoldTextField(pif['metrics']['device_name'])
            if pif['metrics']['carrier']:
                inPane.AddWrappedTextField(Lang("(connected)"))
            else:
                inPane.AddWrappedTextField(Lang("(not connected)"))
                
            inPane.AddStatusField(Lang("MAC Address", 16), pif['macaddr'])
            inPane.AddStatusField(Lang("Device", 16), pif['device'])
            inPane.NewLine()
        
    def Register(self):
        Importer.RegisterNamedPlugIn(
            self,
            'DISPLAY_NICS', # Key of this plugin for replacement, etc.
            {
                'menuname' : 'MENU_NETWORK',
                'menupriority' : 700,
                'menutext' : Lang('Display NICs'),
                'statusupdatehandler' : XSFeatureDisplayNICs.StatusUpdateHandler
            }
        )

# Register this plugin when module is imported
XSFeatureDisplayNICs().Register()
