if __name__ == "__main__":
	raise Exception("This script is a plugin for xsconsole and cannot run independently")
	
from XSConsoleStandard import *

class NetworkResetDialogue(Dialogue):
	def __init__(self):
		Dialogue.__init__(self)
		data = Ubuntu1204Data.Inst()
		data.Update() # Pick up current 'connected' states
		choiceDefs = []

		# Determine primary NIC interface
		self.device = data.derived.managementpifs()[0]['device']

		self.modeMenu = Menu(self, None, Lang("Select IP Address Configuration Mode"), [
			ChoiceDef(Lang("DHCP"), lambda: self.HandleModeChoice('DHCP') ),
			ChoiceDef(Lang("Static"), lambda: self.HandleModeChoice('STATIC') )
			])
		
		# Get best guess of current values
		self.mode = 'DHCP'
		self.IP = '0.0.0.0'
		self.netmask = '0.0.0.0'
		self.gateway = '0.0.0.0'
		self.dns = '0.0.0.0'
		
		self.ChangeState('INITIAL')
				
	def BuildPane(self):
		pane = self.NewPane(DialoguePane(self.parent))
		pane.TitleSet(Lang("Emergency Network Reset"))
		pane.AddBox()

	def UpdateFieldsINITIAL(self):
		pane = self.Pane()
		pane.ResetFields()
		
		pane.AddTitleField(Lang("!! WARNING !!"))
		pane.AddWrappedTextField(Lang("This command will reset its network configuration."))
		pane.NewLine()
		pane.AddWrappedTextField(Lang("Any active network connection might be impacted."))
		pane.NewLine()
		pane.AddKeyHelpField( { Lang("<Enter>") : Lang("Continue"), Lang("<Esc>") : Lang("Cancel") } )

	def UpdateFieldsDEVICE(self):
		pane = self.Pane()
		pane.ResetFields()
		
		pane.AddTitleField(Lang("Enter the Primary Network Interface to be used after reset"))
		pane.AddInputField(Lang("Device name",  14),  self.device, 'device')
		pane.AddKeyHelpField( { Lang("<Enter>") : Lang("OK"), Lang("<Esc>") : Lang("Cancel") } )
		if pane.InputIndex() is None:
			pane.InputIndexSet(0) # Activate first field for input

	def UpdateFieldsMODE(self):
		pane = self.Pane()
		pane.ResetFields()
		
		pane.AddTitleField(Lang("Select the IP configuration mode to be used after reset"))
		pane.AddMenuField(self.modeMenu)
		pane.AddKeyHelpField( { Lang("<Enter>") : Lang("OK"), Lang("<Esc>") : Lang("Cancel") } )

	def UpdateFieldsSTATICIP(self):
		pane = self.Pane()
		pane.ResetFields()
		pane.AddTitleField(Lang("Enter static IP address configuration"))
		pane.AddInputField(Lang("IP Address",  14),  self.IP, 'IP')
		pane.AddInputField(Lang("Netmask",  14),  self.netmask, 'netmask')
		pane.AddInputField(Lang("Gateway",  14),  self.gateway, 'gateway')
		pane.AddInputField(Lang("DNS Server",  14),  self.dns, 'dns')
		pane.AddKeyHelpField( { Lang("<Enter>") : Lang("OK"), Lang("<Esc>") : Lang("Cancel") } )
		if pane.InputIndex() is None:
			pane.InputIndexSet(0) # Activate first field for input
					
	def UpdateFieldsPRECOMMIT(self):
		pane = self.Pane()
		pane.ResetFields()

		pane.AddWrappedTextField(Lang("Press <Enter> to reset the network configuration."))
		pane.NewLine()

		pane.AddWrappedTextField(Lang("The Primary Management Interface will be reconfigured with the following settings:"))
		pane.AddStatusField(Lang("NIC",  16),  self.device)
		pane.AddStatusField(Lang("IP Mode",  16),  self.mode)
		if self.mode == 'static':
			pane.AddStatusField(Lang("IP Address",  16),  self.IP)
			pane.AddStatusField(Lang("Netmask",  16),  self.netmask)
			pane.AddStatusField(Lang("Gateway",  16),  self.gateway)
			pane.AddStatusField(Lang("DNS Server",  16),  self.dns)
								
		pane.AddKeyHelpField( { Lang("<Enter>") : Lang("Apply Changes and Reset"), Lang("<Esc>") : Lang("Cancel") } )
					
	def UpdateFields(self):
		self.Pane().ResetPosition()
		getattr(self, 'UpdateFields'+self.state)() # Despatch method named 'UpdateFields'+self.state
	
	def ChangeState(self, inState):
		self.state = inState
		self.BuildPane()
		self.UpdateFields()

	def HandleKeyINITIAL(self, inKey):
		handled = True
		pane = self.Pane()
		if inKey == 'KEY_ENTER':
			self.ChangeState('DEVICE')
		elif inKey == 'KEY_ESCAPE':
			handled = False
		else:
			pass # Leave handled as True
		return handled

	def HandleKeyDEVICE(self, inKey):
		handled = True
		pane = self.Pane()
		if inKey == 'KEY_ENTER':
			inputValues = pane.GetFieldValues()
			self.device = inputValues['device']
			if self.device == "":
				pane.InputIndexSet(None)
				Layout.Inst().PushDialogue(InfoDialogue(Lang('Invalid device name')))
			else:
				self.ChangeState('MODE')
		elif pane.CurrentInput().HandleKey(inKey):
			pass # Leave handled as True
		else:
			handled = False
		return handled

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
				self.dns = inputValues['dns']
				try:
					failedName = Lang('IP Address')
					IPUtils.AssertValidIP(self.IP)
					failedName = Lang('Netmask')
					IPUtils.AssertValidNetmask(self.netmask)
					failedName = Lang('Gateway')
					IPUtils.AssertValidIP(self.gateway)
					failedName = Lang('DNS Server')
					IPUtils.AssertValidIP(self.dns)
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

	def HandleKeyPRECOMMIT(self, inKey):
		handled = True
		pane = self.Pane()
		if inKey == 'KEY_ENTER':
			self.Commit()
		else:
			handled = False
		return handled
		
	def HandleKey(self,  inKey):
		handled = False
		if hasattr(self, 'HandleKey'+self.state):
			handled = getattr(self, 'HandleKey'+self.state)(inKey)
		
		if not handled and inKey == 'KEY_ESCAPE':
			Layout.Inst().PopDialogue()
			handled = True

		return handled

	def HandleModeChoice(self,  inChoice):
		if inChoice == 'DHCP':
			self.mode = 'dhcp'
			self.ChangeState('PRECOMMIT')
		else:
			self.mode = 'static'
			self.ChangeState('STATICIP')
			
	def Commit(self):
		data = Ubuntu1204Data.Inst()

		# update system network config file
		conf = {
			"device": self.device,
			"configmode": self.mode.lower()
		}
		if self.mode.lower() == 'static':
			conf["ipaddr"]  = self.IP
			conf["netmask"] = self.netmask
			conf["gateway"] = self.gateway
			conf["dns"]     = self.dns
		
		Layout.Inst().TransientBanner(Lang('Network Reset...'))
		(status, output) = data.UpdateNetConf(conf)
		if status:
			Layout.Inst().PushDialogue(InfoDialogue(Lang("Network Reset Successful"), output))
		else:
			XSLogFailure('Network Reset failed ', str(output))
			Layout.Inst().PushDialogue(InfoDialogue(Lang("Network Reset failed"), output))
		
class XSFeatureNetworkReset:
	@classmethod
	def StatusUpdateHandler(cls, inPane):
		data = Ubuntu1204Data.Inst()
		warning = """This command will reset its network configuration.

Any active network connection might be impacted."""
		inPane.AddTitleField(Lang("Emergency Network Reset"))
		inPane.AddWrappedTextField(warning)
				
		inPane.AddKeyHelpField( {
			Lang("<Enter>") : Lang("Reset Networking")
		} )
	
	@classmethod
	def ActivateHandler(cls):
		DialogueUtils.AuthenticatedOnly(lambda: Layout.Inst().PushDialogue(NetworkResetDialogue()))
		
	def Register(self):
		Importer.RegisterNamedPlugIn(
			self,
			'EMERGENCY_NETWORK_RESET', # Key of this plugin for replacement, etc.
			{
				'menuname' : 'MENU_NETWORK',
				'menupriority' : 800,
				'menutext' : Lang('Emergency Network Reset') ,
				'needsauth' : False,
				'statusupdatehandler' : XSFeatureNetworkReset.StatusUpdateHandler,
				'activatehandler' : XSFeatureNetworkReset.ActivateHandler
			}
		)

# Register this plugin when module is imported
XSFeatureNetworkReset().Register()
