if __name__ == "__main__":
    raise Exception("This script is a plugin for xsconsole and cannot run independently")
    
from XSConsoleStandard import *

class XSFeatureDNS:
    @classmethod
    def StatusUpdateHandler(cls, inPane):
        data = Ubuntu1204Data.Inst()
        inPane.AddTitleField(Lang("DNS Servers"))
    
        inPane.AddTitleField(Lang("Current Nameservers"))
        if len(data.dns.nameservers([])) == 0:
            inPane.AddWrappedTextField(Lang("<No nameservers are configured>"))
        for dns in data.dns.nameservers([]):
            inPane.AddWrappedTextField(str(dns))
        inPane.NewLine()
        inPane.AddKeyHelpField( {
            Lang("<F5>") : Lang("Refresh")
        })
        
    def Register(self):
        Importer.RegisterNamedPlugIn(
            self,
            'DNS', # Key of this plugin for replacement, etc.
            {
                'menuname' : 'MENU_NETWORK',
                'menupriority' : 200,
                'menutext' : Lang('Display DNS Servers') ,
                'statusupdatehandler' : self.StatusUpdateHandler,
            }
        )

# Register this plugin when module is imported
XSFeatureDNS().Register()
