# dot-acl
Simple Acl library for actions in "dot" notation, i.e. action is presents as 'resource.access'

You can add acl rules using wildcard '*" instead of resource or access,

Valid examples:
```php
$acl->allow('superadmin', '*.*');
$acl->allow('user', 'user.*');
$acl->allow('operator', '*.read');
$acl->allow('visitor', 'post.view');
```

Also, you can use '!' mark before action name for reverse access, i.e.
```php
$acl->allow('user', '!admin.*'); // is the same as $acl->deny('user', 'admin.*')
$acl->deny('admin', '!admin.*'); // is the same as $acl->allow('admin', 'admin.*')
```
It is useful when you store all acl rules in single array and process
it by only `$acl->allow` or `$acl->deny` function.
 
Usage Example
-------------

```php
include "vendor/autoload.php";

use SZonov\DotAcl\Acl;

$acl = new Acl();

$acl->setDefaultAction(false);

$acl->addRole('guest');
$acl->addRole('user');

$acl->addRole('admin', 'user');

$acl->allow('guest', 'system.index');
$acl->allow('guest', 'public.*');
$acl->allow('user', 'auth.logout');
$acl->allow('admin', '*.*');

echo "-------------- ALL ROLES -------------- \n";
print_r($acl->getRoles());

echo "------ ALLOWED TO public.index -------- \n";
print_r($acl->getAllowedRoles('public.index'));

echo "\n------ guest::system.index -------- \n";
var_export($acl->isAllowed('guest','system.index'));

echo "\n------ user::system.index -------- \n";
var_export($acl->isAllowed('user','system.index'));
echo "\n";

// output:
// -------------- ALL ROLES --------------
// Array
// (
//    [0] => guest
//    [1] => user
//    [2] => admin
// )
// ------ ALLOWED TO public.index --------
// Array
// (
//    [0] => guest
//    [1] => admin
// )
//   
// ------ guest::system.index --------
// true
// ------ user::system.index --------
// false
```
