/**
 * @name Tracked python source extraction inventory
 * @description AST/module presence inventory, not proof of complete semantics or security.
 * @kind table
 * @id aru/tracked-extraction-inventory-python
 */
import python

from File f
select f.getRelativePath(), count(Module n | n.getFile() = f)
