from binderhub.repoproviders import FakeProvider

c.BinderHub.use_registry = False
c.BinderHub.builder_required = False
# c.BinderHub. build_docker_host = " tcp://192.168.137.1:2375"
#c.BinderHub.repo_providers = {'gh': FakeProvider}
c.BinderHub.build_image = '172.16.185.31:30002/jupyter/repo2docker:20180529'
# c.BinderHub.tornado_settings.update({'fake_build':True})

c.BinderHub.about_message = "<blink>Hello world.</blink>"
c.BinderHub.auth_enabled = True