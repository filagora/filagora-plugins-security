<?php

declare(strict_types=1);

namespace Filagora\PluginsSecurity\Support;

use Filagora\Core\Support\UserModel;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;

/**
 * How a person is named in a staff note.
 */
final class Names
{
    public static function of(?Authenticatable $user): string
    {
        if ($user instanceof Model) {
            $name = $user->getAttribute(UserModel::titleAttribute());

            if (is_string($name) && $name !== '') {
                return $name;
            }
        }

        return __('filagora-plugins-security::messages.a_moderator');
    }
}
