if __name__ == "__main__":
    raise Exception("This script is a plugin for xsconsole and cannot run independently")
    
from XSConsoleStandard import *

class InterfaceDialogue(Dialogue):
    def __init__(self):
        Dialogue.__init__(self)
        data = Ubuntu1204Data.Inst()
        data.Update() # Pick up current 'connected' states
        choiceDefs = []

        self.nic=None
        self.converting = False
        currentPIF = None
        choiceArray = []

	    # nic menu
        for i in range(len(data.host.PIFs([]))):
            pif = data.host.PIFs([])[i]
            if currentPIF is None and pif['management']:
                self.nic = i # Record this as best guess of current NIC
                currentPIF = pif
            choiceName = pif['device']+": "+pif['metrics']['device_name']+" "
            if pif['metrics']['carrier']:
                choiceName += '('+Lang("connected")+')'
            else:
                choiceName += '('+Lang("not connected")+')'

            choiceDefs.append(ChoiceDef(choiceName, lambda: self.HandleNICChoice(self.nicMenu.ChoiceIndex())))
        
        if len(choiceDefs) == 0:
            XSLog('Configure Management Interface found no PIFs to present')
            choiceDefs.append(ChoiceDef(Lang("<No interfaces present>"), None))
        else:
            choiceDefs.append(ChoiceDef(Lang("Disable Management Interface"), lambda: self.HandleNICChoice(None)))

        self.nicMenu = Menu(self, None, "Configure Management Interface", choiceDefs)
        
	    # mode menu
        self.modeMenu = Menu(self, None, Lang("Select IP Address Configuration Mode"), [
            ChoiceDef(Lang("DHCP"), lambda: self.HandleModeChoice('DHCP2') ), 
            ChoiceDef(Lang("DHCP with Manually Assigned Hostname"), lambda: self.HandleModeChoice('DHCPMANUAL') ), 
            ChoiceDef(Lang("Static"), lambda: self.HandleModeChoice('STATIC') )
            ])
        
        self.postDHCPMenu = Menu(self, None, Lang("Accept or Edit"), [
            ChoiceDef(Lang("Continue With DHCP Enabled"), lambda: self.HandlePostDHCPChoice('CONTINUE') ), 
            ChoiceDef(Lang("Convert to Static Addressing"), lambda: self.HandlePostDHCPChoice('CONVERT') ), 
            ])
        
        #self.postHostnameMenu = Menu(self, None, Lang("Assign Name"), [
        #    ChoiceDef(Lang("Copy Hostname to ")+data.derived.app_name()+Lang(' Name'),
        #        lambda: self.HandlePostHostnameChoice('COPY') ), 
        #    ChoiceDef(Lang("Keep the Current ")+data.derived.app_name()+Lang(' Name'),
        #        lambda: self.HandlePostHostnameChoice('KEEP') ), 
        #    ChoiceDef(Lang("Enter a New ")+data.derived.app_name()+Lang(' Name'),
        #        lambda: self.HandlePostHostnameChoice('NEW') ),
        #    ])
        
        self.ChangeState('INITIAL')

        # Get best guess of current values
        self.mode = 'DHCP'
        self.IP = '0.0.0.0'
        self.netmask = '0.0.0.0'
        self.gateway = '0.0.0.0'
        self.hostname = data.host.hostname('')
        
        if currentPIF is not None:
            if 'configmode' in currentPIF: self.mode = currentPIF['configmode']
            if self.mode.lower().startswith('static'):
                if 'ipaddr' in currentPIF: self.IP = currentPIF['ipaddr']
                if 'netmask' in currentPIF: self.netmask = currentPIF['netmask']
                if 'gateway' in currentPIF: self.gateway = currentPIF['gateway']
    
        # Make the menu current choices point to our best guess of current choices
        if self.nic is not None:
            self.nicMenu.CurrentChoiceSet(self.nic)
        if self.mode.lower().startswith('static'):
            self.modeMenu.CurrentChoiceSet(2)
        else:
            self.modeMenu.CurrentChoiceSet(0)
            
        if self.mode.lower().startswith('dhcp') and self.nic is not None:
            self.nicMenu.AddChoice(name = Lang('Renew DHCP Lease On Current Interface'),
                onAction = lambda: self.HandleRenewChoice()
                )
    
        self.ChangeState('INITIAL')
        
    def BuildPane(self):
        pane = self.NewPane(DialoguePane(self.parent))
        pane.TitleSet(Lang("Management Interface Configuration"))
        pane.AddBox()
        
    def UpdateFieldsINITIAL(self):
        pane = self.Pane()
        pane.ResetFields()
        
        pane.AddTitleField(Lang("Select NIC for Management Interface"))
        pane.AddMenuField(self.nicMenu)
        pane.AddKeyHelpField( { Lang("<Enter>") : Lang("OK"), Lang("<Esc>") : Lang("Cancel") } )

    def UpdateFieldsMODE(self):
        pane = self.Pane()
        pane.ResetFields()
        
        pane.AddTitleField(Lang("Select DHCP or static IP address configuration"))
        pane.AddMenuField(self.modeMenu)
        pane.AddKeyHelpField( { Lang("<Enter>") : Lang("OK"), Lang("<Esc>") : Lang("Cancel") } )
        
    def UpdateFieldsSTATICIP(self):
        pane = self.Pane()
        pane.ResetFields()
        if self.converting:
            pane.AddTitleField(Lang("Please confirm or edit the static IP configuration"))
        else:
            pane.AddTitleField(Lang("Enter static IP address configuration"))
        pane.AddInputField(Lang("IP Address",  14),  self.IP, 'IP')
        pane.AddInputField(Lang("Netmask",  14),  self.netmask, 'netmask')
        pane.AddInputField(Lang("Gateway",  14),  self.gateway, 'gateway')
        pane.AddInputField(Lang("Hostname",  14),  self.hostname, 'hostname')
        pane.AddKeyHelpField( { Lang("<Enter>") : Lang("OK"), Lang("<Esc>") : Lang("Cancel") } )
        if pane.InputIndex() is None:
            pane.InputIndexSet(0) # Activate first field for input
        
    def UpdateFieldsHOSTNAME(self):
        pane = self.Pane()
        pane.ResetFields()
        pane.AddTitleField(Lang("Enter the hostname for this server"))
        pane.AddInputField(Lang("Hostname",  14),  Ubuntu1204Data.Inst().host.hostname(''), 'hostname')
        pane.AddKeyHelpField( { Lang("<Enter>") : Lang("OK"), Lang("<Esc>") : Lang("Cancel") } )        
        if pane.InputIndex() is None:
            pane.InputIndexSet(0) # Activate first field for input
            
    def UpdateFieldsPRECOMMIT(self):
        pane = self.Pane()
        pane.ResetFields()
        
        pane.AddTitleField(Lang("Press <Enter> to apply the following configuration"))

        if self.nic is None:
            pane.AddWrappedTextField(Lang("The Management Interface will be disabled"))
        else:
            pif = Ubuntu1204Data.Inst().host.PIFs()[self.nic]
            pane.AddStatusField(Lang("Device",  16),  pif['device'])
            pane.AddStatusField(Lang("Name",  16),  pif['metrics']['device_name'])
            pane.AddStatusField(Lang("IP Mode",  16),  self.mode)
            if self.mode == 'Static':
                pane.AddStatusField(Lang("IP Address",  16),  self.IP)
                pane.AddStatusField(Lang("Netmask",  16),  self.netmask)
                pane.AddStatusField(Lang("Gateway",  16),  self.gateway)
                
            if self.mode != 'Static' and self.hostname == '':
                pane.AddStatusField(Lang("Hostname",  16), Lang("Assigned by DHCP"))
            else:
                pane.AddStatusField(Lang("Hostname",  16), self.hostname)
                
        pane.AddKeyHelpField( { Lang("<Enter>") : Lang("OK"), Lang("<Esc>") : Lang("Cancel") } )
        
    def UpdateFieldsPOSTDHCP(self):
        pane = self.Pane()
        pane.ResetFields()
   
        pane.AddWrappedBoldTextField(Lang("The following addresses have been assigned by DHCP.  Would you like to accept them and continue with DHCP enabled, or convert to a static configuration?"))
        pane.NewLine()

        if self.nic is None:
            pane.AddWrappedTextField(Lang("<No interface configured>"))
        else:
            pif = Ubuntu1204Data.Inst().host.PIFs()[self.nic]
            pane.AddStatusField(Lang("Device",  16),  pif['device'])
            pane.AddStatusField(Lang("Name",  16),  pif['metrics']['device_name'])
            pane.AddStatusField(Lang("IP Address",  16),  self.IP)
            pane.AddStatusField(Lang("Netmask",  16),  self.netmask)
            pane.AddStatusField(Lang("Gateway",  16),  self.gateway)
            pane.AddStatusField(Lang("Hostname",  16),  self.hostname)
        pane.NewLine()
        pane.AddMenuField(self.postDHCPMenu)
        pane.AddKeyHelpField( { Lang("<Enter>") : Lang("OK"), Lang("<Esc>") : Lang("Cancel") } )
    
    def UpdateFields(self):
        self.Pane().ResetPosition()
        getattr(self, 'UpdateFields'+self.state)() # Despatch method named 'UpdateFields'+self.state
    
    def ChangeState(self, inState):
        self.state = inState
        self.BuildPane()
        self.UpdateFields()
                            
    def HandleKeyINITIAL(self, inKey):
        return self.nicMenu.HandleKey(inKey)

    def HandleKeyMODE(self, inKey):
        return self.modeMenu.HandleKey(inKey)

    def HandleKeySTATICIP(self, inKey):
        handled = True
        pane = self.Pane()
        if inKey == 'KEY_ENTER':
            if pane.IsLastInput():
                inputValues = pane.GetFieldValues()
                self.IP = inputValues['IP']
                self.netmask = inputValues['netmask']
                self.gateway = inputValues['gateway']
                self.hostname = inputValues['hostname']
                try:
                    failedName = Lang('IP Address')
                    IPUtils.AssertValidIP(self.IP)
                    failedName = Lang('Netmask')
                    IPUtils.AssertValidNetmask(self.netmask)
                    failedName = Lang('Gateway')
                    IPUtils.AssertValidIP(self.gateway)
                    failedName = Lang('Hostname')
                    IPUtils.AssertValidNetworkName(self.hostname)
                    self.ChangeState('PRECOMMIT')
                except:
                    pane.InputIndexSet(None)
                    Layout.Inst().PushDialogue(InfoDialogue(Lang('Invalid ')+failedName))

            else:
                pane.ActivateNextInput()
        elif inKey == 'KEY_TAB':
            pane.ActivateNextInput()
        elif inKey == 'KEY_BTAB':
            pane.ActivatePreviousInput()
        elif pane.CurrentInput().HandleKey(inKey):
            pass # Leave handled as True
        else:
            handled = False
        return handled

    def HandleKeyHOSTNAME(self, inKey):
        handled = True
        pane = self.Pane()
        if inKey == 'KEY_ENTER':
            inputValues = pane.GetFieldValues()
            self.hostname = inputValues['hostname']
            try:
                IPUtils.AssertValidNetworkName(self.hostname)
                self.ChangeState('PRECOMMIT')
            except:
                pane.InputIndexSet(None)
                Layout.Inst().PushDialogue(InfoDialogue(Lang('Invalid hostname')))
                
        elif pane.CurrentInput().HandleKey(inKey):
            pass # Leave handled as True
        else:
            handled = False
        return handled

    def HandleKeyPRECOMMIT(self, inKey):
        handled = True
        pane = self.Pane()
        if inKey == 'KEY_ENTER':
            Layout.Inst().TransientBanner( Lang("Reconfiguring network..."))
            try:
                self.Commit()
                if self.mode == 'DHCP':
                    data = Ubuntu1204Data.Inst()
                    self.IP = data.derived.managementpifs()[0]['ipaddr']
                    self.netmask = data.derived.managementpifs()[0]['netmask']
                    self.gateway = data.derived.managementpifs()[0]['gateway']
                    self.ChangeState('POSTDHCP')
                else:
                    self.Complete() # Disabled management interface
                
            except Exception, e:
                self.Complete(Lang("Configuration Failed: "+Lang(e)))
                
        else:
            handled = False
        return handled
    
    def HandleKeyPOSTDHCP(self, inKey):
        return self.postDHCPMenu.HandleKey(inKey)
    
    def HandleKey(self,  inKey):
        handled = False
        if hasattr(self, 'HandleKey'+self.state):
            handled = getattr(self, 'HandleKey'+self.state)(inKey)
        
        if not handled and inKey == 'KEY_ESCAPE':
            Layout.Inst().PopDialogue()
            handled = True

        return handled
            
    def HandleNICChoice(self,  inChoice):
        self.nic = inChoice
        if self.nic is None:
            self.ChangeState('PRECOMMIT')
        else:
            self.ChangeState('MODE')
        
    def HandleModeChoice(self,  inChoice):
        self.hostname = ''
        if inChoice == 'DHCP2': # DHCP with DHCP-assigned hostname
            self.mode = 'DHCP'
            self.ChangeState('PRECOMMIT')
        elif inChoice == 'DHCPMANUAL': # DHCP with manually assigned hostname
            self.mode = 'DHCP'
            self.ChangeState('HOSTNAME')
        elif inChoice == 'STATIC':
            self.hostname = Ubuntu1204Data.Inst().host.hostname('')
            self.mode = 'Static'
            self.ChangeState('STATICIP')

    def HandlePostDHCPChoice(self,  inChoice):
        if inChoice == 'CONTINUE':
	    self.Complete()
        elif inChoice == 'CONVERT':
            self.converting = True
            self.mode = 'Static'
            self.ChangeState('STATICIP')

    def HandleRenewChoice(self):
        data = Ubuntu1204Data.Inst()
        pif = data.host.PIFs()[self.nic]
        
        Layout.Inst().PopDialogue()
        Layout.Inst().TransientBanner(Lang('Renewing DHCP Lease...'))

        (status, output) = data.RenewDHCPLease(pif['device'])
        if status:
            data.Update()
            ipAddress = data.host.address('')
            if ipAddress == '':
                ipAddress = Lang('<Unknown>')
            Layout.Inst().PushDialogue(InfoDialogue(Lang("DHCP Renewed with IP address ")+ipAddress))
    	else:
            Layout.Inst().PushDialogue(InfoDialogue(Lang("Renewal Failed"), output))
            
    def Commit(self):
        data = Ubuntu1204Data.Inst()
        if self.nic is None:
            self.mode = None
            for pif in data.derived.managementpifs([]):
                data.DisableInterface(pif['device'])
        else:
            pif = data.host.PIFs()[self.nic]
            if self.mode.lower().startswith('static'):
                # Comma-separated list of nameserver IPs
                dns = ','.join(data.dns.nameservers([]))
            else:
                dns = ''
                
            # Operation of the dhclient-script is:
            # If the current hostname from bin/hostname is '(none)', 'localhost' or 'localhost.localdomain',
            # get the hostname from DHCP, otherwise keep the current hostname.  So we set the hostname
            # here to control the action of DHCP when ReconfigureManagement runs
            if self.hostname == '':
                 # DHCP will override if the DHCP server offers a hostname, otherwise we'll keep this one
                data.HostnameSet('localhost')
            else:                
                data.HostnameSet(self.hostname)

	    conf = {
                "device": pif['device'],
                "configmode": self.mode
            }
            if self.mode.lower().startswith('static'):
                conf["ipaddr"]  = self.IP
                conf["netmask"] = self.netmask
                conf["gateway"] = self.gateway
                conf["dns"]     = dns
            data.UpdateNetConf(conf)

        data.Update()
        self.hostname = data.host.hostname('') # Hostname may have changed.  Must be after data.Update()

    def Complete(self, inMessage = None):
        Layout.Inst().PopDialogue()
        Layout.Inst().PushDialogue(InfoDialogue(FirstValue(inMessage, Lang("Network Configuration Successful"))))

class XSFeatureInterface:
    @classmethod
    def StatusUpdateHandler(cls, inPane):
        data = Ubuntu1204Data.Inst()
        
        inPane.AddTitleField(Lang("Configure Management Interface"))

        if len(data.derived.managementpifs([])) == 0:
            inPane.AddWrappedTextField(Lang("<No interface configured>"))
        else:
            for pif in data.derived.managementpifs([]):
                inPane.AddStatusField(Lang('Device', 16), pif['device'])
                inPane.AddStatusField(Lang('MAC Address', 16),  pif['macaddr'])
                inPane.AddStatusField(Lang('DHCP/Static IP', 16),  pif['configmode'])

                inPane.AddStatusField(Lang('IP address', 16), pif['ipaddr'])
                inPane.AddStatusField(Lang('Netmask', 16),  pif['netmask'])
                inPane.AddStatusField(Lang('Gateway', 16),  pif['gateway'])
                inPane.AddStatusField(Lang('Hostname', 16),  data.host.hostname(''))
                
                inPane.NewLine()
                inPane.AddTitleField(Lang("NIC Vendor"))
                inPane.AddWrappedTextField(pif['metrics']['vendor_name'])
                inPane.NewLine()
                inPane.AddTitleField(Lang("NIC Model"))
                inPane.AddWrappedTextField(pif['metrics']['device_name'])
                
        inPane.AddKeyHelpField( {
            Lang("<Enter>") : Lang("Reconfigure"),
            Lang("<F5>") : Lang("Refresh")
        } )
    
    @classmethod
    def ActivateHandler(cls):
        DialogueUtils.AuthenticatedOnly(lambda: Layout.Inst().PushDialogue(InterfaceDialogue()))
        
    def Register(self):
        Importer.RegisterNamedPlugIn(
            self,
            'SELECT_MANAGEMENT_INTERFACE', # Key of this plugin for replacement, etc.
            {
                'menuname' : 'MENU_NETWORK',
                'menupriority' : 50,
                'menutext' : Lang('Configure Management Interface') ,
                'needsauth' : True,
                'statusupdatehandler' : XSFeatureInterface.StatusUpdateHandler,
                'activatehandler' : XSFeatureInterface.ActivateHandler
            }
        )

# Register this plugin when module is imported
XSFeatureInterface().Register()
