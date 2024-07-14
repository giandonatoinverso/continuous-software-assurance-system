import subprocess
import yaml


class ComposeUtils:
    def __init__(self, compose_file_path, env_file_path=None):
        self.compose_file_path = compose_file_path
        self.env_file_path = env_file_path
        if env_file_path is not None:
            self.env_vars = self.read_env_variables()
        else:
            self.env_vars = None

    def get_images_list(self):
        if self.env_vars is not None:
            self.replace_env_variables()

        with open(self.compose_file_path, 'r') as f:
            compose_data = yaml.safe_load(f)

        images = []
        for service_name, service_config in compose_data.get('services', {}).items():
            image_name = service_config.get('image')
            if image_name:
                images.append(image_name)

        return images

    def read_env_variables(self):
        env_vars = {}
        with open(self.env_file_path, 'r') as file:
            for line in file:
                if line.strip() and not line.startswith('#'):
                    parts = line.split('=', 1)
                    env_var = parts[0].strip()
                    value = parts[1].strip()
                    env_vars[env_var] = value

        return env_vars

    def replace_env_variables(self):
        with open(self.compose_file_path, 'r') as input_file:
            input_data = yaml.safe_load(input_file)

        output_data = self.replace_env_vars_recursively(input_data)

        with open(self.compose_file_path, 'w') as output_file:
            yaml.dump(output_data, output_file)

    def replace_env_vars_recursively(self, data):
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, str):
                    for env_var, env_value in self.env_vars.items():
                        data[key] = data[key].replace('${' + env_var + '}', env_value)
                else:
                    data[key] = self.replace_env_vars_recursively(value)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                data[i] = self.replace_env_vars_recursively(item)

        return data
