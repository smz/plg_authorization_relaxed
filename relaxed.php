<?php
/**
 * "Relaxed" authentication plugin
 *
 * This authentication plugin accepts not only the "real" user password
 * but also two variations that could result from CAPS-LOCK being wrongly engaged
 * or some smartphone/tablet forcing the capitalization of the entered password.
 *
 * As an example, if the "real" password is "mySecretPassword", also "MYsECRETpASSWORD"
 * and "MySecretPassword" will be accepted as valid.
 *
 * Due to the "relaxed" acceptation rules a small security reduction is introduced which
 * will be more than compensated by adding a single character to any password.
 *
 * @copyright   Copyright (c) 2016 Sergio Manzi
 *
 * @copyright   Copyright (C) 2005 - 2016 Open Source Matters, Inc. All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 */

defined('_JEXEC') or die;

class PlgAuthenticationRelaxed extends JPlugin
{
	/**
	 * This method should handle any authentication and report back to the subject
	 *
	 * @param   array   $credentials  Array holding the user credentials
	 * @param   array   $options      Array of extra options
	 * @param   object  &$response    Authentication response object
	 *
	 * @return  void
	 *
	 * @since   1.5
	 */
	public function onUserAuthenticate($credentials, $options, &$response)
	{
		$response->type = 'Relaxed';

		// Joomla does not like blank passwords
		if (empty($credentials['password']))
		{
			$response->status        = JAuthentication::STATUS_FAILURE;
			$response->error_message = JText::_('JGLOBAL_AUTH_EMPTY_PASS_NOT_ALLOWED');

			return;
		}

		// Get a database object
		$db    = JFactory::getDbo();
		$query = $db->getQuery(true)
			->select('id, password')
			->from('#__users')
			->where('username=' . $db->quote($credentials['username']));

		$db->setQuery($query);
		$result = $db->loadObject();

		if ($result)
		{
			// Check the password as entered
			$match = JUserHelper::verifyPassword($credentials['password'], $result->password, $result->id);

			// Check the password with flipped characters case (in case of CAPS-LOCK)
			$flipped_chars = preg_split('/(?<!^)(?!$)/u', $credentials['password']);
			$fixed_chars = $flipped_chars;

			foreach ($flipped_chars as $key => $original)
			{
				$flipped = mb_strtolower($original, "UTF-8");
				if ($flipped == $original)
				{
					$flipped = mb_strtoupper($original, 'UTF-8');
				}
				$flipped_chars[$key] = $flipped;
			}

			$flipped_password = implode('', $flipped_chars);
			$match_flipped = JUserHelper::verifyPassword($flipped_password, $result->password, $result->id);

			// Check the password with the first (position 0) character lower-cased (in case of broken IME)
			$fixed_chars[0] = mb_strtolower($fixed_chars[0], 'UTF-8');
			$fixed_password = implode('', $fixed_chars);
			$match_fixed = JUserHelper::verifyPassword($fixed_password, $result->password, $result->id);

			if ($match === true || $match_flipped === true || $match_fixed === true)
			{
				// Bring this in line with the rest of the system
				$user               = JUser::getInstance($result->id);
				$response->email    = $user->email;
				$response->fullname = $user->name;

				if (JFactory::getApplication()->isAdmin())
				{
					$response->language = $user->getParam('admin_language');
				}
				else
				{
					$response->language = $user->getParam('language');
				}

				$response->status        = JAuthentication::STATUS_SUCCESS;
				$response->error_message = '';
			}
			else
			{
				// Invalid password
				$response->status        = JAuthentication::STATUS_FAILURE;
				$response->error_message = JText::_('JGLOBAL_AUTH_INVALID_PASS');
			}
		}
		else
		{
			// Invalid user
			$response->status        = JAuthentication::STATUS_FAILURE;
			$response->error_message = JText::_('JGLOBAL_AUTH_NO_USER');
		}

		// Check the two factor authentication
		if ($response->status == JAuthentication::STATUS_SUCCESS)
		{
			require_once JPATH_ADMINISTRATOR . '/components/com_users/helpers/users.php';

			$methods = UsersHelper::getTwoFactorMethods();

			if (count($methods) <= 1)
			{
				// No two factor authentication method is enabled
				return;
			}

			require_once JPATH_ADMINISTRATOR . '/components/com_users/models/user.php';

			$model = new UsersModelUser;

			// Load the user's OTP (one time password, a.k.a. two factor auth) configuration
			if (!array_key_exists('otp_config', $options))
			{
				$otpConfig             = $model->getOtpConfig($result->id);
				$options['otp_config'] = $otpConfig;
			}
			else
			{
				$otpConfig = $options['otp_config'];
			}

			// Check if the user has enabled two factor authentication
			if (empty($otpConfig->method) || ($otpConfig->method == 'none'))
			{
				// Warn the user if he's using a secret code but he has not
				// enabed two factor auth in his account.
				if (!empty($credentials['secretkey']))
				{
					try
					{
						$app = JFactory::getApplication();

						$this->loadLanguage();

						$app->enqueueMessage(JText::_('PLG_AUTH_JOOMLA_ERR_SECRET_CODE_WITHOUT_TFA'), 'warning');
					}
					catch (Exception $exc)
					{
						// This happens when we are in CLI mode. In this case
						// no warning is issued
						return;
					}
				}

				return;
			}

			// Load the Joomla! RAD layer
			if (!defined('FOF_INCLUDED'))
			{
				include_once JPATH_LIBRARIES . '/fof/include.php';
			}

			// Try to validate the OTP
			FOFPlatform::getInstance()->importPlugin('twofactorauth');

			$otpAuthReplies = FOFPlatform::getInstance()->runPlugins('onUserTwofactorAuthenticate', array($credentials, $options));

			$check = false;

			/*
			 * This looks like noob code but DO NOT TOUCH IT and do not convert
			 * to in_array(). During testing in_array() inexplicably returned
			 * null when the OTEP begins with a zero! o_O
			 */
			if (!empty($otpAuthReplies))
			{
				foreach ($otpAuthReplies as $authReply)
				{
					$check = $check || $authReply;
				}
			}

			// Fall back to one time emergency passwords
			if (!$check)
			{
				// Did the user use an OTEP instead?
				if (empty($otpConfig->otep))
				{
					if (empty($otpConfig->method) || ($otpConfig->method == 'none'))
					{
						// Two factor authentication is not enabled on this account.
						// Any string is assumed to be a valid OTEP.

						return;
					}
					else
					{
						/*
						 * Two factor authentication enabled and no OTEPs defined. The
						 * user has used them all up. Therefore anything he enters is
						 * an invalid OTEP.
						 */
						return;
					}
				}

				// Clean up the OTEP (remove dashes, spaces and other funny stuff
				// our beloved users may have unwittingly stuffed in it)
				$otep  = $credentials['secretkey'];
				$otep  = filter_var($otep, FILTER_SANITIZE_NUMBER_INT);
				$otep  = str_replace('-', '', $otep);
				$check = false;

				// Did we find a valid OTEP?
				if (in_array($otep, $otpConfig->otep))
				{
					// Remove the OTEP from the array
					$otpConfig->otep = array_diff($otpConfig->otep, array($otep));

					$model->setOtpConfig($result->id, $otpConfig);

					// Return true; the OTEP was a valid one
					$check = true;
				}
			}

			if (!$check)
			{
				$response->status        = JAuthentication::STATUS_FAILURE;
				$response->error_message = JText::_('JGLOBAL_AUTH_INVALID_SECRETKEY');
			}
		}
	}
}
