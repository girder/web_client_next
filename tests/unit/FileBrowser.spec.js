import MockAdapter from 'axios-mock-adapter';
import { shallowMount } from '@vue/test-utils';
import RestClient from '@/rest';
import FileBrowser from '@/components/FileBrowser.vue';
import { flushPromises, girderVue } from './utils';

const localVue = girderVue();

function getMockUserResponse(userId) {
  return {
    admin: true,
    created: '2018-09-07T19:35:02.275000+00:00',
    email: 'foo@kitware.com',
    emailVerified: true,
    firstName: 'Foo',
    groupInvites: [],
    groups: [],
    lastName: 'User',
    login: 'foo',
    otp: false,
    public: true,
    size: 104502538,
    status: 'enabled',
    _accessLevel: 2,
    _id: userId,
    _modelType: 'user',
  };
}

function getMockFolderResponse(parentId, parentCollection = 'user') {
  return {
    _accessLevel: 2,
    _id: 'fake_folderId',
    _modelType: 'folder',
    baseParentId: 'fake_baseParentId',
    baseParentType: 'user',
    created: '2018-09-07T19:35:02.502000+00:00',
    creatorId: 'fake_creatorId',
    description: '',
    name: 'Private',
    parentCollection,
    parentId,
    public: false,
    size: 104221409,
    updated: '2018-09-07T19:35:02.502000+00:00',
  };
}

function getMockFolderQueryResponse(count = 1) {
  return (new Array(count)).fill(getMockFolderResponse());
}

function getMockItemResponse() {
  return {
    baseParentId: 'fake_baseParentId',
    baseParentType: 'user',
    created: '2018-10-10T13:23:54.490000+00:00',
    creatorId: 'fake_creatorId',
    description: '',
    folderId: '5bb3b5c289f99f5de63c8295',
    name: 'activity_group_Joining_Queue_073,61.json',
    size: 848,
    updated: '2018-10-10T13:23:54.490000+00:00',
    _id: 'fake_itemId',
    _modelType: 'item',
  };
}

function getMockItemQueryResponse(count = 1) {
  return (new Array(count)).fill(getMockItemResponse());
}

describe('File Browser', () => {
  const girderRest = new RestClient();
  const mock = new MockAdapter(girderRest);

  afterEach(() => {
    mock.reset();
  });

  it('can handle normal navigation', async () => {
    mock
      .onGet(/user\/foo_user_id/)
      .reply(200, getMockUserResponse('foo_user_id'))
      .onGet(/user\/foo_user_id\/details/)
      .replyOnce(200, { nFolders: 1 })
      .onGet(/folder\/fake_folder_id/)
      .reply(200, getMockFolderResponse('foo_user_id'))
      .onGet(/folder\/fake_folder_id\/details/)
      .replyOnce(200, { nFolders: 1, nItems: 1 })
      .onGet(/folder/)
      .reply(200, getMockFolderQueryResponse(1))
      .onGet(/item/)
      .reply(200, getMockItemQueryResponse(1));
    const wrapper = shallowMount(FileBrowser, {
      localVue,
      propsData: {
        location: {
          type: 'user',
          id: 'foo_user_id',
        },
        selectEnabled: false,
        multiSelectEnabled: false,
        uploadEnabled: false,
        newItemEnabled: false,
        newFolderEnabled: false,
      },
      provide: { girderRest },
    });
    await flushPromises();
    const { location } = wrapper.vm.$options.props;
    expect(location.required).toBeTruthy();
    expect(location.type).toBe(Object);
    expect(wrapper.vm.rows.length).toBe(1);
    expect(wrapper.vm.breadcrumb.path.length).toBe(0);
    expect(wrapper.vm.breadcrumb.root.id).toBe('foo_user_id');

    // Change location, and check that FileBrowser reacts accordingly.
    wrapper.vm.location = {
      type: 'folder',
      id: 'fake_folder_id',
    };
    await flushPromises();
    expect(wrapper.vm.location.type).toBe('folder');
    expect(wrapper.vm.breadcrumb.path.length).toBe(1);
    expect(wrapper.vm.breadcrumb.root.id).toBe('foo_user_id');
    expect(wrapper.vm.rows.length).toBe(2); // 1 folder, 1 item
  });
});