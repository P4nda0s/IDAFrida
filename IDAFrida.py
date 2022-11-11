import idaapi

###################
# from: https://github.com/igogo-x86/HexRaysPyTools
class ActionManager(object):
    def __init__(self):
        self.__actions = []

    def register(self, action):
        self.__actions.append(action)
        idaapi.register_action(
                idaapi.action_desc_t(action.name, action.description, action, action.hotkey)
            )

    def initialize(self):
        pass

    def finalize(self):
        for action in self.__actions:
            idaapi.unregister_action(action.name)

action_manager = ActionManager()


class Action(idaapi.action_handler_t):
    """
    Convenience wrapper with name property allowing to be registered in IDA using ActionManager
    """
    description = None
    hotkey = None

    def __init__(self):
        super(Action, self).__init__()

    @property
    def name(self):
        return "FridaIDA:" + type(self).__name__

    def activate(self, ctx):
        # type: (idaapi.action_activation_ctx_t) -> None
        raise NotImplementedError

    def update(self, ctx):
        # type: (idaapi.action_activation_ctx_t) -> None
        raise NotImplementedError

############################################################################
import ida_funcs
import json
import os

from PyQt5 import QtCore
from PyQt5.Qt import QApplication
from PyQt5.QtWidgets import QDialog, QHBoxLayout, QVBoxLayout, QTextEdit

# [offset] => offset of target function in hex value format.
# [funcname] => function name
# [filename] => input file name of IDA. e.g. xxx.so / xxx.exe 

default_template = """

(function () {

    // @ts-ignore
    function print_arg(addr) {
        try {
            var module = Process.findRangeByAddress(addr);
            if (module != null) return "\\n"+hexdump(addr) + "\\n";
            return ptr(addr) + "\\n";
        } catch (e) {
            return addr
        }
    }

    // @ts-ignore
    function hook_native_addr(funcPtr, paramsNum) {
        var module = Process.findModuleByAddress(funcPtr);
        try {
            Interceptor.attach(funcPtr, {
                onEnter: function (args) {
                    this.logs = "";
                    this.params = [];
                    // @ts-ignore
                    this.logs=this.logs.concat("So: " + module.name + "  Method base: " + ptr(funcPtr).sub(module.base) + "\\n");
                    for (let i = 0; i < paramsNum; i++) {
                        this.params.push(args[i]);
                        this.logs=this.logs.concat("this.args" + i + " onEnter: " + print_arg(args[i]));
                    }
                }, onLeave: function (retval) {
                    for (let i = 0; i < paramsNum; i++) {
                        this.logs=this.logs.concat("this.args" + i + " onLeave: " + print_arg(this.params[i]));
                    }
                    this.logs=this.logs.concat("retval onLeave: " + print_arg(retval) + "\\n");
                    console.log(this.logs);
                }
            });
        } catch (e) {
            console.log(e);
        }
    }
    // @ts-ignore
    hook_native_addr(Module.findBaseAddress("[filename]").add([offset]), [nargs]);
})();

    """



class Configuration:
    def __init__(self) -> None:
        self.frida_cmd = """frida -U --attach-name="com.example.app" -l gen.js --no-pause"""
        self.template = default_template
        if os.path.exists("IDAFrida.json"):
            self.load()

    def set_frida_cmd(self, s):
        self.frida_cmd = s
        self.store()

    def set_template(self, s):
        self.template = s
        self.store()

    def reset(self):
        self.__init__()
    
    def store(self):
        try:
            data = {"frida_cmd" : self.frida_cmd, "template": self.template}
            open("IDAFrida.json", "w").write(json.dumps(data))
        except Exception as e:
            print(e)

    def load(self):
        try:
            data = json.loads(open("IDAFrida.json", "r").read())
            self.frida_cmd = data["frida_cmd"]
            self.template = data["template"]
        except Exception as e:
            print(e)


global_config = Configuration()

class ConfigurationUI(QDialog):
    def __init__(self, conf : Configuration) -> None:
        super(ConfigurationUI, self).__init__()
        self.conf = conf
        self.edit_template = QTextEdit()
        self.edit_template.setPlainText(self.conf.template)
        layout = QHBoxLayout()
        layout.addWidget(self.edit_template)
        self.setLayout(layout)

    def closeEvent(self, a0) -> None:
        self.conf.set_template(self.edit_template.toPlainText())
        self.conf.store()
        return super().closeEvent(a0)



class ScriptGenerator:
    def __init__(self, configuration : Configuration) -> None:
        self.conf = configuration
        self.imagebase=idaapi.get_imagebase()

    @staticmethod
    def get_idb_filename():
        return os.path.basename(idaapi.get_input_file_path())
    
    @staticmethod
    def get_idb_path():
        return os.path.dirname(idaapi.get_input_file_path())

    def generate_stub(self, repdata: dict):
        s = self.conf.template
        for key, v in repdata.items():
            s = s.replace("[%s]" % key, v)
        return s

    def generate_for_funcs(self, func_addr_list) -> str:
        stubs = []
        for func_addr in func_addr_list:
            repdata = {
                "filename" : self.get_idb_filename(),
                "funcname" : ida_funcs.get_func_name(func_addr),
                "offset" : hex(func_addr-self.imagebase),
                "nargs": hex(idaapi.decompile(func_addr).type.get_nargs()) 
            }
            stubs.append(self.generate_stub(repdata))
        return "\n".join(stubs)

    def generate_for_funcs_to_file(self, func_addr_list, filename) -> bool:
        data = self.generate_for_funcs(func_addr_list)
        try:
            open(filename, "w").write(data)
            print("The generated Frida script has been exported to the file: ",filename)
        except Exception as e:
            print(e)
            return False
        try:
            QApplication.clipboard().setText(data)
            print("The generated Frida script has been copied to the clipboard!")
        except Exception as e:
            print(e)
            return False
        return True


class Frida:
    def __init__(self, conf: Configuration) -> None:
        self.conf = conf

class IDAFridaMenuAction(Action):
    TopDescription = "IDAFrida"
    def __init__(self):
        super(IDAFridaMenuAction, self).__init__()

    def activate(self, ctx) -> None:
        raise NotImplemented

    def update(self, ctx) -> None:
        if ctx.form_type == idaapi.BWN_FUNCS:
            idaapi.attach_action_to_popup(ctx.widget, None, self.name, self.TopDescription + "/")
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET
    
class GenerateFridaHookScript(IDAFridaMenuAction):
    description = "Generate Frida Script"
    def __init__(self):
        super(GenerateFridaHookScript, self).__init__()

    def activate(self, ctx):
        gen = ScriptGenerator(global_config)
        idb_path = os.path.dirname(idaapi.get_input_file_path())
        out_file = os.path.join(idb_path, "IDAhook.js")
        selected = [idaapi.getn_func(idx).start_ea for idx in ctx.chooser_selection] #from "idaapi.getn_func(idx - 1)" to "idaapi.getn_func(idx)"
        gen.generate_for_funcs_to_file(selected, out_file)


class RunGeneratedScript(IDAFridaMenuAction):
    description = "Run Generated Script"
    def __init__(self):
        super(RunGeneratedScript, self).__init__()

    def activate(self, ctx):
        print("template")

class ViewFridaTemplate(IDAFridaMenuAction):
    description = "View Frida Template"
    def __init__(self):
        super(ViewFridaTemplate, self).__init__()

    def activate(self, ctx):
        ui = ConfigurationUI(global_config)
        ui.show()
        ui.exec_()

class SetFridaRunCommand(IDAFridaMenuAction):
    description = "Set Frida Command"

    def __init__(self):
        super(SetFridaRunCommand, self).__init__()

    def activate(self, ctx):
        print("template")
    

action_manager.register(GenerateFridaHookScript())
# action_manager.register(RunGeneratedScript())
action_manager.register(ViewFridaTemplate())
# action_manager.register(SetFridaRunCommand())
