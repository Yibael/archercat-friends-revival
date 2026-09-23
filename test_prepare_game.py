import unittest
from pathlib import Path
from unittest.mock import patch
from tools import prepare_game


class PrepareGameTests(unittest.TestCase):
    def test_valid_installation_does_not_import_again(self):
        with patch.object(prepare_game, 'installed_app') as app, patch.object(prepare_game, 'verify_app', return_value=True), patch.object(prepare_game.subprocess, 'run') as run:
            app.return_value.exists.return_value = True
            self.assertEqual(prepare_game.prepare(), app.return_value)
            run.assert_not_called()

    def test_invalid_existing_installation_is_never_replaced(self):
        with patch.object(prepare_game, 'installed_app') as app, patch.object(prepare_game, 'verify_app', return_value=False), patch.object(prepare_game.subprocess, 'run') as run:
            app.return_value.exists.return_value = True
            with self.assertRaises(RuntimeError): prepare_game.prepare()
            run.assert_not_called()

    def test_missing_noninteractive_installation_stops_before_import(self):
        with patch.object(prepare_game, 'installed_app') as app, patch.object(prepare_game.subprocess, 'run') as run:
            app.return_value.exists.return_value = False
            with self.assertRaises(RuntimeError): prepare_game.prepare(noninteractive=True)
            run.assert_not_called()

    def test_first_import_uses_bundled_ipa_once_then_returns(self):
        with patch.object(prepare_game, 'installed_app') as app, patch.object(prepare_game, 'verify_app', return_value=True), patch.object(prepare_game, 'verify_ipa', return_value=Path('/bundle/game.ipa')), patch.object(prepare_game, 'find_playcover', return_value=Path('/Applications/PlayCover.app')), patch.object(prepare_game.subprocess, 'run') as run:
            app.return_value.exists.side_effect = [False, False, True]
            self.assertEqual(prepare_game.prepare(), app.return_value)
            run.assert_called_once_with(['open','-a','/Applications/PlayCover.app','/bundle/game.ipa'], check=True, timeout=20)

    def test_import_race_preserves_new_installation(self):
        with patch.object(prepare_game, 'installed_app') as app, patch.object(prepare_game, 'verify_ipa', return_value=Path('/bundle/game.ipa')), patch.object(prepare_game, 'find_playcover', return_value=Path('/Applications/PlayCover.app')), patch.object(prepare_game.subprocess, 'run') as run:
            app.return_value.exists.side_effect = [False, True]
            with self.assertRaises(RuntimeError): prepare_game.prepare()
            run.assert_not_called()

    def test_import_timeout_never_repeats_import(self):
        with patch.object(prepare_game, 'installed_app') as app, patch.object(prepare_game, 'verify_ipa', return_value=Path('/bundle/game.ipa')), patch.object(prepare_game, 'find_playcover', return_value=Path('/Applications/PlayCover.app')), patch.object(prepare_game.subprocess, 'run') as run:
            app.return_value.exists.return_value = False
            with self.assertRaises(RuntimeError): prepare_game.prepare(timeout=0)
            self.assertEqual(run.call_count, 1)


if __name__ == '__main__': unittest.main()
