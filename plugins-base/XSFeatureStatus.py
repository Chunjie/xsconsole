if __name__ == "__main__":
    raise Exception("This script is a plugin for xsconsole and cannot run independently")
    
from XSConsoleStandard import *

class XSFeatureStatus:
    @classmethod
    def StatusUpdateHandler(cls, inPane):
        data = Ubuntu1204Data.Inst()

        inPane.AddWrappedTextField(data.dmi.system_manufacturer())
        inPane.AddWrappedTextField(data.dmi.system_product_name())
        inPane.NewLine()
        inPane.AddWrappedTextField(Language.Inst().Branding(data.derived.brand()) + ' ' +
            data.derived.fullversion())
        inPane.NewLine()
        inPane.AddTitleField(Lang("Management Network Parameters"))
        
        if len(data.derived.managementpifs([])) == 0:
            inPane.AddWrappedTextField(Lang("<No network configured>"))
        else:
            inPane.AddStatusField(Lang('Device', 16), data.derived.managementpifs()[0]['device'])
            inPane.AddStatusField(Lang('IP address', 16), data.derived.managementpifs()[0]['ipaddr'])
            inPane.AddStatusField(Lang('Netmask', 16),  data.derived.managementpifs()[0]['netmask'])
            inPane.AddStatusField(Lang('Gateway', 16),  data.derived.managementpifs()[0]['gateway'])
        
        inPane.NewLine()
        inPane.AddWrappedTextField(Lang('Press <Enter> to display the SSL key fingerprints for this host'))
    
        inPane.AddKeyHelpField( { Lang("<F5>") : Lang("Refresh"), Lang("<Enter>") : Lang("Fingerprints")})

    @classmethod
    def ActivateHandler(cls):
        data = Ubuntu1204Data.Inst()
        appName = data.derived.app_name('')

        message = ''
        message += Lang('Key fingerprint shown when connecting from '+appName+' (https)\n\n')
        message += data.sslfingerprint('')+'\n\n'
        message += Lang('Key fingerprint shown when logging in remotely (ssh)\n\n')
        message += data.sshfingerprint('')

        Layout.Inst().PushDialogue(InfoDialogue(Lang("SSL Key Fingerprints"), message))

    def Register(self):
        Importer.RegisterNamedPlugIn(
            self,
            'STATUS', # Key of this plugin for replacement, etc.
            {
                'menuname' : 'MENU_ROOT',
                'menupriority' : 50,
                'menutext' : Lang('Status Display'),
                'statusupdatehandler' : XSFeatureStatus.StatusUpdateHandler,
                'activatehandler' : XSFeatureStatus.ActivateHandler
            }
        )

# Register this plugin when module is imported
XSFeatureStatus().Register()
