import angr
import monkeyhex


p = angr.Project('/home/smr/new_cfg/app',load_options={'auto_load_libs':False})
cfg= p.analyses.CFGFast()
#cfg= p.analyses.CFGFast()


entry_func =  cfg.kb.functions[p.entry]


print("graph", cfg.graph)
print("nodes %d edges %d" % (len(cfg.graph.nodes()), len(cfg.graph.edges())))

print("entry", entry_func)

all_nodes= cfg.get_all_nodes(p.entry) 

print("all", all_nodes)
#print("predeccessors:", entry_func.predecessors)
#print("successors:", entry_func.successors)
print("type of jump", [jumpkind + "to" + str(node.addr) for node, jumpkind in cfg.get_successors_and_jumpkind(entry_func) ])

