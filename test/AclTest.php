<?php
namespace SZonov\DotAcl\Test;

use PHPUnit\Framework\TestCase;
use SZonov\DotAcl\Acl;

class AclTest extends TestCase
{
    /**
     * @var Acl
     */
    private $acl;

    public function setUp() {
        $this->acl = new Acl();
        foreach ($this->stub() as $role => $config)
        {
            $inherits = array_shift($config);
            $this->acl->addRole($role, $inherits);
            foreach ($config as $action)
                $this->acl->allow($role, $action);
        }
    }

    public function testGetDefaultAction()
    {
        $this->assertTrue($this->acl->getDefaultAction());
    }

    public function testSetDefaultAction()
    {
        $currentDefaultAction = $this->acl->getDefaultAction();

        $acl = $this->acl->setDefaultAction(true);

        $this->assertSame(get_class($acl), Acl::class);
        $this->assertTrue($acl->getDefaultAction());

        $acl = $this->acl->setDefaultAction(false);

        $this->assertSame(get_class($acl), Acl::class);
        $this->assertFalse($acl->getDefaultAction());

        $acl = $this->acl->setDefaultAction($currentDefaultAction);

        $this->assertSame(get_class($acl), Acl::class);
        $this->assertSame($currentDefaultAction, $acl->getDefaultAction());
    }

    public function testAddRole()
    {
        $acl = new Acl();

        $acl->addRole('First');
        $acl->addRole('Second', ['Developer']);
        $acl->addRole('Third', ['Developer']);

        $this->assertCount(4, $acl->getRoles());

        $this->assertTrue(in_array('First', $acl->getRoles()));
        $this->assertTrue(in_array('Second', $acl->getRoles()));
        $this->assertTrue(in_array('Third', $acl->getRoles()));
        $this->assertTrue(in_array('Developer', $acl->getRoles()));
    }


    public function testAddInherit()
    {
        $acl = new Acl();
        $acl->addInherit('First', 'Zero');
        $acl->addInherit('Next', 'Zero');

        $this->assertCount(3, $acl->getRoles());

        $this->assertTrue(in_array('First', $acl->getRoles()));
        $this->assertTrue(in_array('Zero', $acl->getRoles()));
        $this->assertTrue(in_array('Next', $acl->getRoles()));
    }

    public function testGetRoles()
    {
        $roles = $this->acl->getRoles();

        $this->assertCount(6, $roles);

        $this->assertTrue(in_array('Unauthorized', $roles));
        $this->assertTrue(in_array('Authorized', $roles));
        $this->assertTrue(in_array('Administrator', $roles));
        $this->assertTrue(in_array('Developer', $roles));
        $this->assertTrue(in_array('Programmer', $roles));
        $this->assertTrue(in_array('Master', $roles));
    }

    public function testIsAllowed()
    {
        $this->acl->setDefaultAction(true);

        $this->assertTrue($this->acl->isAllowed('Unauthorized', 'routes.root'));
        $this->assertTrue($this->acl->isAllowed('Unauthorized', 'routes2.root'));

        $this->acl->setDefaultAction(false);

        $this->assertTrue($this->acl->isAllowed('Unauthorized', 'routes.root'));
        $this->assertFalse($this->acl->isAllowed('Unauthorized', 'routes2.root'));

        $this->assertTrue($this->acl->isAllowed('Unauthorized', 'Album.find'));
        $this->assertFalse($this->acl->isAllowed('Unauthorized', 'user.me'));

        $this->assertTrue($this->acl->isAllowed('Authorized', 'user.me'));

        $this->assertTrue($this->acl->isAllowed('Authorized', 'export.documentation_json'));

        $this->assertTrue($this->acl->isAllowed('Master', 'export.documentation_json'));

        $this->assertTrue($this->acl->isAllowed('Developer', 'demo.new'));
        $this->assertTrue($this->acl->isAllowed('Developer', 'export.documentation_html'));

        $this->assertFalse($this->acl->isAllowed('Developer', 'export.documentation_xml'));
        $this->assertTrue($this->acl->isAllowed('Programmer', 'export.documentation_xml'));

        $this->assertFalse($this->acl->isAllowed('Developer', 'Photo.find'));

        $this->assertTrue($this->acl->isAllowed('Administrator', 'Photo.find'));
        $this->assertTrue($this->acl->isAllowed('Master', 'Photo.find'));

    }

    public function testAllow()
    {
        $this->acl->setDefaultAction(false);

        $this->assertFalse($this->acl->isAllowed('Developer', 'new.success'));
        $this->assertFalse($this->acl->isAllowed('Developer', 'new.other'));

        $this->acl->allow('Developer', 'new.*');

        $this->assertTrue($this->acl->isAllowed('Developer', 'new.success'));
        $this->assertTrue($this->acl->isAllowed('Developer', 'new.other'));

    }

    public function testDeny()
    {
        $this->acl->setDefaultAction(false);

        $this->assertTrue($this->acl->isAllowed('Developer', 'Album.all'));
        $this->assertTrue($this->acl->isAllowed('Developer', 'Album.find'));

        $this->acl->deny('Developer', 'Album.find');

        $this->assertTrue($this->acl->isAllowed('Developer', 'Album.all'));
        $this->assertFalse($this->acl->isAllowed('Developer', 'Album.find'));
    }

    public function testGetAllowedRoles()
    {
        $this->acl->setDefaultAction(false);

        $found = $this->acl->getAllowedRoles('album.browse');

        $expected = ['Administrator', 'Developer', 'Master'];
        $this->assertSame($expected, $found);

        $found = $this->acl->getAllowedRoles('export.documentation_json');

        $expected = [
            'Unauthorized',
            'Authorized',
            'Administrator',
            'Developer',
            'Programmer',
            'Master'
        ];
        $this->assertSame($expected, $found);
    }

    public function stub()
    {
        return [
            'Unauthorized' => [ null,
              'routes.*',
              'export.documentation_html',
              'export.documentation_json',
              'export.postman_json',
              'Album.all',
              'Album.find',
              '!user.me',
            ],
            'Authorized' => [ 'Unauthorized',
                'user.me',
            ],
            'Administrator' => [ 'Authorized',
                '*.*'
            ],
            'Developer' => [ 'Authorized',
                'user.find',
                'album.find',
                'album.browse',
                'demo.*',
                '!*.browse',
            ],
            'Programmer' => [ 'Authorized',
                'export.*',

            ],
            'Master' => [ [ 'Developer', 'Programmer' ],
                'Photo.find'
            ]
        ];
    }
}
