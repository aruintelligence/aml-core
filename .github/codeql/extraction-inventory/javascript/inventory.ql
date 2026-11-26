/**
 * @name Tracked javascript source extraction inventory
 * @description AST/module presence inventory, not proof of complete semantics or security.
 * @kind table
 * @id aru/tracked-extraction-inventory-javascript
 */
import javascript

from File f
select f.getRelativePath(), count(TopLevel n | n.getFile() = f)
