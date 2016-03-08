module VeriCiteID
  def generate_vericite_id!
    # the reason we don't just use the global_id all the time is so that the
    # vericite_id is preserved when shard splits/etc. occur
    vericite_id || update_attribute(:vericite_id, global_id)
  end

  def vericite_asset_string
    generate_vericite_id!
    "#{self.class.reflection_type_name}_#{vericite_id}"
  end
end
