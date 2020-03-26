<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInitbba42e22aa4f85cd29bdcedc6d88ee5a
{
    public static $prefixLengthsPsr4 = array (
        'M' => 
        array (
            'MVC\\' => 4,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'MVC\\' => 
        array (
            0 => __DIR__ . '/../..' . '/application',
        ),
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInitbba42e22aa4f85cd29bdcedc6d88ee5a::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInitbba42e22aa4f85cd29bdcedc6d88ee5a::$prefixDirsPsr4;

        }, null, ClassLoader::class);
    }
}
