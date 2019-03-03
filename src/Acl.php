<?php

namespace SZonov\DotAcl;

/**
 *
 * Simple acl library for actions in "dot" notation, i.e. action is presents as 'resource.access'
 *
 * You can add acl rules using wildcard '*" instead of resource or access,
 *
 * Valid examples:
 *   $acl->allow('superadmin', '*.*');
 *   $acl->allow('user', 'user.*');
 *   $acl->allow('operator', '*.read');
 *   $acl->allow('visitor', 'post.view');
 *
 * Also, you can use '!' mark before action name for reverse access
 * i.e.
 *  $acl->allow('user', '!admin.*') is the same as $acl->deny('user', 'admin.*')
 *  $acl->deny('admin', '!admin.*') is the same as $acl->allow('admin', 'admin.*')
 *
 */
class Acl
{
    protected $_defaultAccess = true;
    protected $_roles = [];
    protected $_roleInherits = [];
    protected $_access = [];

    /**
     * Sets the default access level (true or false)
     *
     * @param bool $defaultAccess
     * @return $this
     */
    public function setDefaultAction(bool $defaultAccess)
    {
        $this->_defaultAccess = $defaultAccess;
        return $this;
    }

    /**
     *  Returns the default ACL access level
     *
     * @return bool
     */
    public function getDefaultAction()
    {
        return $this->_defaultAccess;
    }

    /**
     * Allow access to a role on an action
     *
     * You can use '*' as wildcard
     *
     * Examples of action: 'system.index' ... 'system.*' .. '*.index', '!system.index'
     *
     * @param string $role
     * @param string $action
     * @return Acl
     */
    public function allow($role, $action)
    {
        return $this->_allowOrDeny($role, $action, true);
    }

    /**
     * Deny access to a role on an action
     *
     * You can use '*' as wildcard
     *
     * Examples of action: 'system.index' ... 'system.*' .. '*.index', '!system.index'
     *
     * @param string $role
     * @param string $action
     * @return Acl
     */
    public function deny($role, $action)
    {
        return $this->_allowOrDeny($role, $action, false);
    }

    /**
     * Setup access to a role on an action
     *
     * @param string $role
     * @param string $action
     * @param bool $isAllowed
     * @return $this
     *
     */
    protected function _allowOrDeny($role, $action, bool $isAllowed)
    {
        if ($action[0] === '!') {
            $action = substr($action, 1);
            $isAllowed = !$isAllowed;
        }
        $this->_access[$this->_key($role, $action)] = $isAllowed;
        return $this;
    }

    /**
     * @param string $role
     * @param null|string|string[] $accessInherits
     * @return $this
     */
    public function addRole($role, $accessInherits = null)
    {
        $this->_roles[$role] = true;

        foreach ((array)$accessInherits as $roleInherit)
            $this->addInherit($role, $roleInherit);

        return $this;
    }

    /**
     * @param string $role
     * @param string $roleInherit
     * @return $this
     */
    public function addInherit($role, $roleInherit)
    {
        // Make sure we know about this role
        $this->_roles[$role] = true;

        // Make sure we know about inherit role
        $this->_roles[$roleInherit] = true;

        // Skip assigning role to itself
        if ($role !== $roleInherit)
            $this->_roleInherits[$role][] = $roleInherit;

        return $this;
    }

    /**
     * Get list of known roles
     *
     * @return array
     */
    public function getRoles()
    {
        return array_keys($this->_roles);
    }

    /**
     * Find access to resource and action for defined role
     *
     * @param string $role
     * @param string $resource
     * @param string $access
     * @return bool|null
     */
    protected function findRoleAccess($role, $resource, $access)
    {
        $checklist = [
            [$resource, $access],
            [$resource, '*'],
            ['*', $access],
            ['*', '*'],
        ];

        foreach ($checklist as $action)
        {
            $result = $this->_access[$this->_key($role , $action)] ?? null;

            if (null !== $result)
                return $result;
        }

        return null;
    }

    /**
     * Find access to resource and action for defined role with checking inherits
     *
     * @param string $role
     * @param string $resource
     * @param string $access
     * @param array $processedRoles
     * @return bool|null
     */
    protected function findInheritAccess($role, $resource, $access, &$processedRoles)
    {
        if (in_array($role, $processedRoles))
            return null;

        $processedRoles[] = $role;

        $result = $this->findRoleAccess($role, $resource, $access);

        if (null !== $result)
            return $result;

        $inherits = $this->_roleInherits[$role] ?? [];

        foreach ($inherits as $inheritRole)
        {
            $result = $this->findInheritAccess($inheritRole, $resource, $access, $processedRoles);

            if (null !== $result)
                return $result;
        }

        return null;
    }

    /**
     * Find final access to resource and action with checking inherits and configuration of defaultAccess
     *
     * @param string $role
     * @param string $resource
     * @param string $access
     * @return bool
     */
    protected function findAccess($role, $resource, $access)
    {
        $processedRoles = [];
        return $this->findInheritAccess($role, $resource, $access, $processedRoles) ?? $this->_defaultAccess;
    }

    /**
     * Check whether a role is allowed to access an action
     *
     * @param string $role
     * @param string $action
     * @return bool
     */
    public function isAllowed($role, $action)
    {
        $data = $this->_split($action);
        return $this->findAccess($role, $data[0], $data[1]);
    }

    /**
     * Returns array of roles allowed to an action
     *
     * @param string $action
     * @return array
     */
    public function getAllowedRoles($action)
    {
        $roles = [];
        $data = $this->_split($action);
        foreach ($this->getRoles() as $role) {
            if ($this->findAccess($role, $data[0], $data[1])) {
                $roles[] = $role;
            }
        }
        return $roles;
    }

    /**
     * Split action name to resource and access and returns array [resource, access]
     *
     * @param string $action
     * @return array
     */
    protected function _split($action)
    {
        $data = explode('.', (string) $action, 2);
        return (count($data) === 2) ? $data : [ '', $data[0] ];
    }

    /**
     * Generate access key for storing in $this->_access
     *
     * @param string $role
     * @param string|array $action
     * @return string
     */
    protected function _key($role, $action)
    {
        if (!is_array($action))
            $action = $this->_split($action);
        return $role . '!' . $action[0] . '!' . $action[1];
    }
}
